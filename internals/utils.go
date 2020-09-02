package internal

import "os"

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
