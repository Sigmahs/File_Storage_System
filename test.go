package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	err3 := u.StoreFile("file1", v)

	if err3 != nil {
		t.Error("length of hmac", err3)
		return
	}

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func Test1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err3 := InitUser("sam", "foober")
	if err3 != nil {
		t.Error("Failed to initialize sam", err3)
		return
	}
	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var v3 []byte
	var accessToken uuid.UUID
	var accessToken2 uuid.UUID
	accessToken, _ = u.ShareFile("file1", "bob")
	u2.ReceiveFile("file2", "alice", accessToken)
	accessToken2, err = u2.ShareFile("file2", "sam")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", accessToken2)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v3, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func Test2(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var accessToken uuid.UUID
	// var v2 []byte

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	u.RevokeFile("file1", "bob")
	_, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from alicelol", err)
		return
	}
	// if reflect.DeepEqual(v, v2) {
	// 	t.Error("Shared file is the same", v, v2)
	// 	return
	// }
}

// func TestRepeatUsers(t *testing.T) {
// 	clear()
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}
// 	u3, err3 := InitUser("bob", "repeateduser")
// 	if err3 == nil {
// 		t.Error("Username already exists", err3)
// 		return
// 	}
// }

// func TestAppend(t *testing.T) {
// 	clear()
// 	u1, err1 := InitUser("alice", "fubar")
// 	if err1 != nil {
// 		t.Error("Failed to initialize user", err1)
// 		return
// 	}
// 	_, wrongpassword1 := GetUser("alice", "fubar1")
// 	if wrongpassword1 == nil {
// 		t.Error("Wrong Password")
// 		return
// 	}

// 	user1, error1 := GetUser("alice", "fubar")
// 	if error1 != nil {
// 		t.Error("Failed to get alice", error1)
// 		return
// 	}

// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}
// 	user2, error2 := GetUser("bob", "foobar")
// 	if error2 != nil {
// 		t.Error("Failed to get bob", error2)
// 		return
// 	}

// 	v := []byte("This is a test")
// 	user1.StoreFile("file1", v)

// 	loadedfile, fileerror := user1.LoadFile("file1")
// 	if fileerror != nil {
// 		t.Error("Failed to load file1")
// 	}
// 	if !reflect.DeepEqual(loadedfile, v) {
// 		t.Error("Shared file is not the same", loadedfile, v)
// 	}

// 	user1.AppendFile("file1", v)
// 	loadappended, appenderror := user1.LoadFile("file1")
// 	if fileerror != nil {
// 		t.Error("Failed to load file1")
// 	}
// 	if reflect.DeepEqual(loadedfile, loadappended) {
// 		t.Error("Append did not append correctly", loadedfile, loadappended)
// 	}

// }
