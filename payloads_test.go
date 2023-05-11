package cfgprofiles

import (
	"io/ioutil"
	"path/filepath"
	"reflect"
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

func Test_multiString_MarshalPlist(t *testing.T) {
	tests := []struct {
		name    string
		m       *multiString
		want    interface{}
		wantErr bool
	}{
		{"zero", &multiString{}, nil, true},
		{"one", &multiString{"test.example.com"}, "test.example.com", false},
		{"multiple", &multiString{"test1.example.com", "test2.example.com"}, []string{"test1.example.com", "test2.example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.MarshalPlist()
			if (err != nil) != tt.wantErr {
				t.Errorf("multiString.MarshalPlist() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("multiString.MarshalPlist() = %v, want %v", got, tt.want)
			}
		})
	}
}
