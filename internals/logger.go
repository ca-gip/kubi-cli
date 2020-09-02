package internal

import (
	"fmt"
	"strings"
)

func LogWhite(msg ...string) {
	coloredLog("97", msg...)
}

func LogYellow(msg ...string) {
	coloredLog("33", msg...)
}

func LogLightGray(msg ...string) {
	coloredLog("37", msg...)
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
	fmt.Printf("\033[1;"+color+"m%v\033[0m\n", strings.Join(msg, ""))
}
