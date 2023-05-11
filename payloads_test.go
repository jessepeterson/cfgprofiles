package cfgprofiles

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/groob/plist"
)

func Test_multiString_UnmarshalPlist_error(t *testing.T) {
	plBytes, err := ioutil.ReadFile(filepath.Join("testdata", "multistring-error.mobileconfig"))
	fatalIf(t, err)

	p := &Profile{}
	err = plist.Unmarshal(plBytes, p)
	if err == nil {
		t.Error("expected an error")
	}

	expectedErrorMessage := "plist: cannot unmarshal 42 into Go value of type cfgprofiles.multiString"
	if err.Error() != expectedErrorMessage {
		t.Errorf("have %q, want %q", err.Error(), expectedErrorMessage)
	}
}
