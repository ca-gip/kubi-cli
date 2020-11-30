package internal

import (
	"fmt"
	"os"
	"strings"
)

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func LogWhite(msg ...string) {
	coloredLog("97", msg...)

}

func LogYellow(msg ...string) {
	coloredLog("33", msg...)
}

func LogBlue(msg ...string) {
	coloredLog("36", msg...)
}

func LogLightGray(msg ...string) {
	coloredLog("37", msg...)
}

func LogNormal(msg ...interface{}) {
	fmt.Println(msg...)
}

func LogLightRed(msg ...string) {
	coloredLog("91", msg...)
}

func LogReturn() {
	fmt.Println()
}

func LogRed(msg ...string) {
	coloredLog("31", msg...)
}

func coloredLog(color string, msg ...string) {
	if isTerminal() {
		fmt.Printf("\033[1;"+color+"m%v\033[0m\n", strings.Join(msg, ""))
	} else {
		fmt.Println(strings.Join(msg, ""))
	}
}
