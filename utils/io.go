package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var stdinReader = bufio.NewReader(os.Stdin)

// ReadLine reads the next line from stdin, passing the prompt into fmt.Print beforehand.
func ReadLine(prompt string) string {
	if len(prompt) > 0 {
		fmt.Print(prompt)
	}
	input, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(input)
}

// ReadNonEmptyLine repeatedly calls readLine and rejects lines with empty input.
func ReadNonEmptyLine(prompt string) string {
	for {
		input := ReadLine(prompt)
		if len(input) > 0 {
			return input
		}
	}
}
