package internal

import (
	"os"
)

func ExitIfError(e error) {
	if e != nil {
		LogRed("\nAn error occured: \n")
		LogRed("\t--------------------------------------------------------------")
		LogLightRed("\t", e.Error())
		LogRed("\t--------------------------------------------------------------\n\n")
		os.Exit(1)
	}
}

const EmptyString = ""

// FileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err){
			return false
		}
		ExitIfError(err)
		os.Exit(1)
	}

	return !info.IsDir()
}
