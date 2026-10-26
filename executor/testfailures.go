package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/oyzuai/fleet/runnerclient"
)

const (
	maxTestFailures = 200
	maxTestText     = 1024
	maxJUnitReport  = 16 << 20 // Matches Oyzu's native report collector.
)

// readTestFailures reads only collected JUnit reports named by a fresh, final
// build manifest. Report paths are relative to the manifest's dist directory;
// source coordinates in the XML are relative to the checkout. Missing or bad
// diagnostics never change the native command's outcome.
func readTestFailures(directory string, previous, current []byte, mask func(string) string) ([]runnerclient.TestFailure, error) {
	if len(current) == 0 || bytes.Equal(previous, current) {
		return nil, nil
	}
	m, err := parseBuildManifest(current)
	if err != nil {
		return nil, err
	}
	var before struct {
		RunID string `json:"runId"`
	}
	_ = json.Unmarshal(previous, &before)
	if m.RunID == "" || m.RunID == before.RunID || (m.Status != "succeeded" && m.Status != "failed" && m.Status != "interrupted") {
		return nil, nil
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("test report checkout is unavailable")
	}
	defer root.Close()
	var failures []runnerclient.TestFailure
	var problems []error
	remaining := int64(maxManifest)
	for _, report := range m.Reports {
		if len(failures) == maxTestFailures {
			break
		}
		if report.Kind != "test" || report.Format != "junit" || report.Status != "collected" {
			continue
		}
		scope := report.Target + ":test"
		if report.Target == "" || len(scope) > 512 || !junitRelative(report.Path) || !outputDigest.MatchString(report.Digest) {
			problems = append(problems, errors.New("a JUnit report has an invalid target, path or digest"))
			continue
		}
		// OpenRoot confines symlink resolution as well as ordinary traversal.
		// The manifest's paths, like artifact paths, are relative to dist.
		name := path.Join(path.Dir(ManifestPath), report.Path)
		data, err := readJUnitReport(root, name, min(int64(maxJUnitReport), remaining))
		if err != nil {
			problems = append(problems, err)
			continue
		}
		remaining -= int64(len(data))
		sum := sha256.Sum256(data)
		if "sha256:"+hex.EncodeToString(sum[:]) != report.Digest {
			problems = append(problems, errors.New("a JUnit report differs from its manifest digest"))
			continue
		}
		parsed, err := junitFailures(data, mask(scope), maxTestFailures-len(failures), mask)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		failures = append(failures, parsed...)
	}
	return failures, errors.Join(problems...)
}

func readJUnitReport(root *os.Root, name string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("JUnit reports exceed the total read limit")
	}
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("a JUnit report is unavailable, not a regular file or exceeds the read limit")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("a JUnit report cannot be opened inside the checkout")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("a JUnit report is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("a JUnit report is unreadable or exceeds the read limit")
	}
	return data, nil
}

type junitLocation struct {
	File string `xml:"file,attr"`
	Path string `xml:"path,attr"`
	Line string `xml:"line,attr"`
}

type junitProblem struct {
	junitLocation
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitCase struct {
	junitLocation
	Name      string         `xml:"name,attr"`
	Classname string         `xml:"classname,attr"`
	Failures  []junitProblem `xml:"failure"`
	Errors    []junitProblem `xml:"error"`
}

// junitFailures accepts testsuite or testsuites roots, including nested suites.
// It uses report attributes only, never guesses a source path from a classname
// or stack trace and never opens a source file named by the XML.
func junitFailures(data []byte, scope string, limit int, mask func(string) string) ([]runnerclient.TestFailure, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	var suites []junitLocation
	var failures []runnerclient.TestFailure
	seen := false
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			if !seen || len(suites) != 0 {
				return nil, errors.New("a JUnit report has no complete suite")
			}
			return failures, nil
		}
		if err != nil {
			return nil, errors.New("a JUnit report is not valid XML")
		}
		switch element := token.(type) {
		case xml.StartElement:
			if len(suites) == 0 && (seen || (element.Name.Local != "testsuite" && element.Name.Local != "testsuites")) {
				return nil, errors.New("a JUnit report has an invalid root")
			}
			switch element.Name.Local {
			case "testsuite", "testsuites":
				location := junitLocation{}
				for _, attribute := range element.Attr {
					if attribute.Name.Space != "" {
						continue
					}
					switch attribute.Name.Local {
					case "file":
						location.File = attribute.Value
					case "path":
						location.Path = attribute.Value
					case "line":
						location.Line = attribute.Value
					}
				}
				if len(suites) > 0 {
					location = inheritJUnitLocation(location, suites[len(suites)-1])
				}
				suites = append(suites, location)
				seen = true
			case "testcase":
				var test junitCase
				if err := d.DecodeElement(&test, &element); err != nil {
					return nil, errors.New("a JUnit testcase is not valid XML")
				}
				location := inheritJUnitLocation(test.junitLocation, suites[len(suites)-1])
				for _, problem := range append(test.Failures, test.Errors...) {
					if len(failures) == limit {
						break
					}
					where := inheritJUnitLocation(problem.junitLocation, location)
					source, line := junitSource(where)
					message := strings.TrimSpace(problem.Message)
					if text := strings.TrimSpace(problem.Text); text != "" && text != message {
						if message != "" {
							message += "\n"
						}
						message += text
					}
					if message == "" {
						message = firstString(problem.Type, "Test failed.")
					}
					failures = append(failures, runnerclient.TestFailure{
						Scope: scope, Name: boundedTestText(mask(firstString(test.Name, "Unnamed test"))),
						Classname: boundedTestText(mask(test.Classname)), Path: mask(source), Line: line,
						Message: boundedTestText(mask(message)),
					})
				}
			default:
				if err := d.Skip(); err != nil {
					return nil, errors.New("a JUnit report is not valid XML")
				}
			}
		case xml.EndElement:
			if element.Name.Local == "testsuite" || element.Name.Local == "testsuites" {
				suites = suites[:len(suites)-1]
			}
		case xml.CharData:
			if len(suites) == 0 && strings.TrimSpace(string(element)) != "" {
				return nil, errors.New("a JUnit report has text outside its suite")
			}
		case xml.Directive:
			return nil, errors.New("a JUnit report contains an unsupported XML directive")
		}
	}
}

func inheritJUnitLocation(location, parent junitLocation) junitLocation {
	if location.File == "" && location.Path == "" {
		location.File, location.Path = parent.File, parent.Path
		if location.Line == "" {
			location.Line = parent.Line
		}
	}
	return location
}

func junitSource(location junitLocation) (string, int) {
	source := firstString(location.File, location.Path)
	if !junitRelative(source) || len(source) > maxTestText || strings.IndexFunc(source, func(r rune) bool { return r < ' ' || r == '\x7f' }) >= 0 {
		return "", 0
	}
	line, err := strconv.Atoi(location.Line)
	if err != nil || line < 1 {
		line = 0
	}
	return source, line
}

// junitRelative keeps report paths and source coordinates portable and relative
// to the checkout without depending on the snapshot transport implementation.
func junitRelative(name string) bool {
	if name == "" || path.IsAbs(name) || strings.ContainsAny(name, "\\:\x00") || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".git" || part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}

func boundedTestText(text string) string {
	text = strings.ToValidUTF8(text, "�")
	if len(text) <= maxTestText {
		return text
	}
	end := maxTestText
	for !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}
