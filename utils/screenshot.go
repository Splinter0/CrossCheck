package utils

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

func findWindowId(name string) string {
	cmd := exec.Command(
		"bash",
		"-c",
		fmt.Sprintf("xwininfo -tree -root | grep '%s' | awk 'NR==1 {print $1}'", name),
	)

	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		log.Println("error getting the window name:", name, err)
		return ""
	}

	// Print the output
	return strings.ReplaceAll(string(output), "\n", "")
}

func FindAndScreenshotWindow(name string) {
	windowId := findWindowId(name)
	cmd := exec.Command(
		"bash",
		"-c",
		fmt.Sprintf("import -window %s /tmp/%s.png", windowId, name),
	)

	output, err := cmd.Output()
	if err != nil {
		log.Println("error taking the screenshot of window", windowId, name, err)
	}

	// Print the output
	log.Println(string(output))
}
