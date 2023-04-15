package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"bytes"

	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//owner + metadata
type FilesStruct struct {
	Owner              []byte
	MetaLocationAsUUID userlib.UUID
	FileHashKey        []byte
	FileSymKey         []byte
	MetaDS             string
}

// User is the structure definition for a user record.
type User struct {
	Username            string
	RSAKey              []byte
	HashKey             []byte
	DigitalSignatureKey []byte
	DSSigner            userlib.DSSignKey
	DSVerifier          userlib.DSVerifyKey
	PrivateKey          userlib.PrivateKeyType
	UserFiles           map[string]FilesStruct
	SharedKeys          map[uuid.UUID]userlib.PrivateKeyType
	// TestField           []byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

//helper functions for padding and unpadding
func SymEncPadder(plaintext []byte) []byte {
	n := userlib.AESBlockSizeBytes - (len(plaintext) % userlib.AESBlockSizeBytes)
	padded := make([]byte, len(plaintext)+n)
	copy(padded, plaintext)
	copy(padded[len(plaintext):], bytes.Repeat([]byte{byte(n)}, n))
	return padded
}

func SymDecUnpad(plaintext []byte) []byte {
	n := int(plaintext[len(plaintext)-1])
	return plaintext[:len(plaintext)-n]
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	userdata.Username = username

	//only want public key
	publicKey, privateKey, _ := userlib.PKEKeyGen()
	userlib.KeystoreSet(userdata.Username, publicKey)

	//Digital Signature Keys for sharing
	DSSignKey, DSVerifyKey, _ := userlib.DSKeyGen()

	//keys
	userdata.RSAKey = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESBlockSizeBytes))
	userdata.HashKey = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySizeBytes))
	userdata.DigitalSignatureKey = userlib.Argon2Key([]byte(password), []byte(username), uint32(16+len(username)))
	userdata.PrivateKey = privateKey
	userdata.DSSigner = DSSignKey
	userdata.DSVerifier = DSVerifyKey

	//initiallizing filemap
	userdata.UserFiles = make(map[string]FilesStruct)

	//initializing temporary keys
	userdata.SharedKeys = make(map[uuid.UUID]userlib.PrivateKeyType)

	//marshalling userdata and making iv
	marshal_data, _ := json.Marshal(userdata)
	iv := make([]byte, userlib.AESBlockSizeBytes+len(marshal_data))
	iv = iv[:userlib.AESBlockSizeBytes]
	copy(iv, userlib.RandomBytes(16))

	//encrypting userdata
	padded_marshal := SymEncPadder(marshal_data)
	userdata_encrypted := userlib.SymEnc(userdata.RSAKey, iv, padded_marshal)

	//Hashes the encrypted data using hashkey
	userdata_hmac, _ := userlib.HashKDF(userdata.HashKey, userdata_encrypted)

	//store encrypted and hashed data appended
	userdata_cipher := append(userdata_encrypted, userdata_hmac...)

	//store userdata in datastore using digital signature (from username)
	userdata_uuid := bytesToUUID(userdata.DigitalSignatureKey)
	userlib.DatastoreSet(userdata_uuid, userdata_cipher)

	//End of toy implementation

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	_, valid := userlib.KeystoreGet(username)

	if !valid {
		return nil, errors.New("no username found")
	}

	tmp_RSAKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESBlockSizeBytes))
	tmp_HashKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySizeBytes))
	tmp_DigitalSignatureKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(len(username)))
	tmp_uuid := bytesToUUID(tmp_DigitalSignatureKey)

	tmp_cipher, valid := userlib.DatastoreGet(tmp_uuid)

	if !valid {
		return nil, errors.New("incorrect Password")
	}

	//separated cipher "unappending"
	tmp_encrypted := tmp_cipher[:(len(tmp_cipher) - userlib.AESKeySizeBytes)]
	tmp_hmac := tmp_cipher[(len(tmp_cipher) - userlib.AESKeySizeBytes):]

	//is the hmac untouched "has the encrypted data been changed"
	generated_tmp_hmac, _ := userlib.HashKDF(tmp_HashKey, tmp_encrypted)
	if !userlib.HMACEqual(tmp_hmac, generated_tmp_hmac) {
		return nil, errors.New("data has no integrity")
	}

	//decrypt
	tmp_encrypted = userlib.SymDec(tmp_RSAKey, tmp_encrypted)
	tmp_encrypted = SymDecUnpad(tmp_encrypted)
	if err := json.Unmarshal(tmp_encrypted[userlib.AESBlockSizeBytes:], userdataptr); err != nil {
		return nil, errors.New("unmarshall error")
	}

	return userdataptr, nil
}

//file struct, may update later
type File struct {
	Data []byte
}

//file metaData, may update later
type MetaData struct {
	Owner           []byte
	File_sym        []byte
	File_hmac       []byte
	FileDSKeyAsUUID uuid.UUID
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	// var unpadded_test MetaData

	metaDSKey := uuid.New().String()
	// return errors.New(strconv.Itoa(len(metaDSKey)))
	fileSymKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.AESBlockSizeBytes))
	fileHashKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.AESKeySizeBytes))
	fileDSKey := userlib.Argon2Key([]byte(metaDSKey), userlib.RandomBytes(36), uint32(len(metaDSKey)))
	pubKey, _ := userlib.KeystoreGet(userdata.Username)

	//encrypt file with user public key
	file := File{data}
	file_marshal, _ := json.Marshal(file)
	file_encrypted, _ := userlib.PKEEnc(pubKey, file_marshal)

	//Hashes the encrypted data using hashkey
	file_hmac, _ := userlib.HashKDF(fileHashKey, file_encrypted)
	// return errors.New(strconv.Itoa(len(file_hmac)))

	//store encrypted and hashed data appended
	file_cipher := append(file_encrypted, file_hmac...)
	// return errors.New(strconv.Itoa(len(file_cipher)))

	//store file in datastore using digital signature
	file_uuid := bytesToUUID([]byte(fileDSKey))
	// userdata.TestField = fileDSKey
	userlib.DatastoreSet(file_uuid, file_cipher)

	//create metadata (for owner, access)
	encryptedOwner, _ := userlib.PKEEnc(pubKey, []byte(userdata.Username))
	MetaData := MetaData{encryptedOwner, fileSymKey, fileHashKey, file_uuid}
	// return errors.New(strconv.Itoa(len(MetaData.file_hmac)))

	//marshalling metadata and making jv
	meta_marshal, _ := json.Marshal(MetaData)
	// json.Unmarshal(meta_marshal, &MetaData)
	// return errors.New(strconv.Itoa(len(MetaData.file_hmac)))
	jv := make([]byte, userlib.AESBlockSizeBytes+len(meta_marshal))
	jv = jv[:userlib.AESBlockSizeBytes]
	copy(jv, userlib.RandomBytes(16))
	// return errors.New(strconv.Itoa(len(meta_marshal)))

	//encrypting metadata with file symmetric key
	padded_marshal := SymEncPadder(meta_marshal)
	metadata_encrypted := userlib.SymEnc(fileSymKey, jv, padded_marshal)
	//return errors.New(string(metadata_encrypted))
	//return errors.New(strconv.Itoa(len(metadata_encrypted)))
	// testdata_decrypted := userlib.SymDec(fileSymKey, metadata_encrypted)
	// testdata_unpadded := SymDecUnpad(testdata_decrypted)
	// json.Unmarshal(testdata_unpadded, &MetaData)
	// return errors.New(strconv.Itoa(len(MetaData.Owner)))
	// return errors.New(strconv.FormatBool(bytes.Equal(meta_marshal, testdata_unpadded)))
	// return errors.New(strconv.Itoa(len(unpadded_test.file_hmac)))
	// return errors.New(strconv.Itoa(len(unpadded_test_data)))
	// return errors.New(strconv.FormatBool(bytes.Equal(unpadded_test_data, test_data)))

	//Hashes the encrypted data using hashkey
	meta_hmac, _ := userlib.HashKDF(fileHashKey, metadata_encrypted)

	//store encrypted and hashed data appended
	metadata_cipher := append(metadata_encrypted, meta_hmac...)
	//return errors.New(strconv.Itoa(len(metadata_cipher)))

	//store metadata in datastore using digital signature
	metadata_uuid := bytesToUUID([]byte(metaDSKey))
	userlib.DatastoreSet(metadata_uuid, metadata_cipher)
	// test, _ := userlib.DatastoreGet(metadata_uuid)
	//return errors.New(strconv.Itoa(len(test)))
	// return errors.New(strconv.Itoa(len(metadata_uuid)))

	//update user information to have the file in it
	userdata.UserFiles[filename] = FilesStruct{encryptedOwner, metadata_uuid, fileHashKey, fileSymKey, metaDSKey}

	//testing file pull
	// metaDSKeyTest := userdata.UserFiles[filename].metaDS
	// fileDSKeyTest := userlib.Argon2Key([]byte(metaDSKeyTest), []byte(metaDSKeyTest), uint32(len(metaDSKeyTest)))
	// fileDSKeyAsUUID := bytesToUUID([]byte(fileDSKeyTest))
	// filedata_cipher, _ := userlib.DatastoreGet(fileDSKeyAsUUID)
	// return errors.New(strconv.FormatBool(bytes.Equal(filedata_cipher, file_cipher)))

	//updating userdata

	//marshalling userdata and making iv
	marshal_data, _ := json.Marshal(userdata)
	iv := make([]byte, userlib.AESBlockSizeBytes+len(marshal_data))
	iv = iv[:userlib.AESBlockSizeBytes]
	copy(iv, userlib.RandomBytes(16))

	//encrypting userdata
	padded_marshal_data := SymEncPadder(marshal_data)
	userdata_encrypted := userlib.SymEnc(userdata.RSAKey, iv, padded_marshal_data)

	//Hashes the encrypted data using hashkey
	userdata_hmac, _ := userlib.HashKDF(userdata.HashKey, userdata_encrypted)

	//store encrypted and hashed data appended
	userdata_cipher := append(userdata_encrypted, userdata_hmac...)

	//store userdata in datastore using digital signature (from username)
	userdata_uuid := bytesToUUID(userdata.DigitalSignatureKey)
	userlib.DatastoreSet(userdata_uuid, userdata_cipher)

	// generated_tmp_hmac, _ := userlib.HashKDF(MetaData.File_hmac, file_encrypted)
	// return errors.New(strconv.FormatBool(userlib.HMACEqual(file_hmac, generated_tmp_hmac)))

	// return errors.New(strconv.FormatBool(bytes.Equal(file_uuid[:], metadata_uuid[:])))
	// return errors.New(strconv.FormatBool(bytes.Equal(metadata_uuid[:], userdata_uuid[:])))
	// test2, _ := userlib.DatastoreGet(metadata_uuid)
	// return errors.New(strconv.FormatBool(bytes.Equal(test, test2)))
	// return errors.New(strconv.FormatBool(bytes.Equal(userdata.DigitalSignatureKey, []byte(metaDSKey))))

	// return errors.New(strconv.Itoa(len(metadata_uuid)))
	// test, _ := userlib.DatastoreGet(metadata_uuid)
	// return errors.New(strconv.Itoa(len(test)))

	//Make sure padding and unpadding works
	// test_data, _ := json.Marshal([]byte("hello"))
	// tv := make([]byte, userlib.AESBlockSizeBytes+len(marshal_data))
	// tv = tv[:userlib.AESBlockSizeBytes]
	// copy(tv, userlib.RandomBytes(16))
	// // return errors.New(strconv.Itoa(len(test_data)))
	// padded_test_data := SymEncPadder(test_data)
	// testdata_encrypted := userlib.SymEnc(fileSymKey, tv, padded_test_data)
	// testdata_decrypted := userlib.SymDec(fileSymKey, testdata_encrypted)
	// unpadded_test_data := SymDecUnpad(testdata_decrypted)
	// // return errors.New(strconv.Itoa(len(unpadded_test_data)))
	// return errors.New(strconv.FormatBool(bytes.Equal(unpadded_test_data, test_data)))
	// return errors.New(strconv.FormatBool(bytes.Equal(userdata.UserFiles[filename].fileSymKey, fileSymKey)))

	//testing file pull
	// metaDSKeyTest := userdata.UserFiles[filename].metaDS
	// fileDSKeyTest := userlib.Argon2Key([]byte(metaDSKeyTest), []byte(metaDSKeyTest), uint32(len(metaDSKeyTest)))
	// fileDSKeyAsUUID := bytesToUUID([]byte(fileDSKeyTest))
	// filedata_cipher, _ := userlib.DatastoreGet(fileDSKeyAsUUID)
	// return errors.New(strconv.FormatBool(bytes.Equal(filedata_cipher, file_cipher)))

	//TODO: This is a toy implementation.
	// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// jsonData, _ := json.Marshal(data)
	// userlib.DatastoreSet(storageKey, jsonData)

	//End of toy implementation

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// 	var metadata MetaData

	// 	//retrieve files from user
	// 	retrieve := userdata.UserFiles[filename]
	// 	metaLocationAsUUID, _ := uuid.FromBytes([]byte(retrieve.MetaLocation))
	// 	metadata_cipher, _ := userlib.DatastoreGet(metaLocationAsString)

	// 	//separated cipher "unappending"
	// 	tmp_encrypted := metadata_cipher[:(len(metadata_cipher) - userlib.HashSizeBytes)]
	// 	tmp_hmac := metadata_cipher[(len(metadata_cipher) - userlib.HashSizeBytes):]

	// 	//is the hmac untouched "has the encrypted data been changed"
	// 	generated_tmp_hmac, _ := userlib.HashKDF(retrieve.meta_hmac, tmp_encrypted)
	// 	if !userlib.HMACEqual(tmp_hmac, generated_tmp_hmac) {
	// 		return errors.New("Data has no integrity")
	// 	}

	// 	//retrieve file data
	// 	fileDSKey := userlib.Argon2Key([]byte(metaDSKey), []byte(metaDSKey), uint32(len(metaDSKey)))

	return err
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	var metagame MetaData

	//retrieve files from user
	retrieve := userdata.UserFiles[filename]
	metadata_cipher, valid := userlib.DatastoreGet(retrieve.MetaLocationAsUUID)
	//return nil, errors.New(strconv.Itoa(len(metadata_cipher)))

	if !valid {
		return nil, errors.New("no such file")
	}

	//separated cipher "unappending"
	tmp_encrypted := metadata_cipher[:(len(metadata_cipher) - userlib.HashSizeBytes)]
	tmp_hmac := metadata_cipher[(len(metadata_cipher) - userlib.HashSizeBytes):]

	//is the hmac untouched "has the encrypted data been changed"
	generated_tmp_hmac, _ := userlib.HashKDF(retrieve.FileHashKey, tmp_encrypted)
	//return nil, errors.New(string(tmp_hmac))
	//return nil, errors.New(string(generated_tmp_hmac))
	//return nil, errors.New(string(tmp_encrypted))
	// return nil, errors.New(strconv.Itoa(len(metadata_cipher)))
	//return nil, errors.New(strconv.Itoa(len(tmp_encrypted)))
	//return nil, errors.New(strconv.Itoa(len(tmp_hmac)))
	//return nil, errors.New(strconv.Itoa(len(generated_tmp_hmac)))

	if !userlib.HMACEqual(tmp_hmac, generated_tmp_hmac) {
		return nil, errors.New("reeee")
	}

	//unecrypt metadata
	tmp_metadata := userlib.SymDec(retrieve.FileSymKey, tmp_encrypted)
	tmp_metadata_unpadded := SymDecUnpad(tmp_metadata)
	// testdata_decrypted := userlib.SymDec(fileSymKey, metadata_encrypted)
	// testdata_unpadded := SymDecUnpad(testdata_decrypted)
	// return nil, errors.New(strconv.Itoa(len(tmp_metadata)))
	ok := json.Unmarshal(tmp_metadata_unpadded, &metagame)
	if ok != nil {
		return nil, errors.New("unmarshall error")
	}
	// return nil, errors.New(strconv.Itoa(len(metagame.File_hmac)))

	//retrieve file data
	// return nil, errors.New(strconv.FormatBool(bytes.Equal(fileDSKey, userdata.TestField)))
	filedata_cipher, valid := userlib.DatastoreGet(metagame.FileDSKeyAsUUID)

	if !valid {
		return nil, errors.New("no File")
	}

	// return nil, errors.New(strconv.Itoa(len(filedata_cipher)))

	//separated cipher "unappending"
	tmp_encrypted_filedata := filedata_cipher[:(len(filedata_cipher) - 64)]
	tmp_hmac_file := filedata_cipher[(len(filedata_cipher) - 64):]

	//is the hmac untouched "has the encrypted data been changed"
	generated_tmp_hmac, _ = userlib.HashKDF(metagame.File_hmac, tmp_encrypted_filedata)
	if !userlib.HMACEqual(tmp_hmac_file, generated_tmp_hmac) {
		return nil, errors.New("data has no integritie2")
	}

	//decrypt
	var file File

	current_user, _ := userlib.PKEDec(userdata.PrivateKey, retrieve.Owner)
	// return nil, errors.New(strconv.Itoa(strings.Compare(string(current_user), userdata.Username)))
	// pubKey, _ := userlib.KeystoreGet(userdata.Username)
	// current_user, _ := userlib.PKEEnc(pubKey, []byte(userdata.Username))
	//return nil, errors.New(strconv.Itoa(len(current_user)))
	//return nil, errors.New(strconv.Itoa(len(metagame.Owner)))
	//return nil, errors.New(strconv.FormatBool(bytes.Equal(retrieve.Owner, current_user)))
	if string(current_user) != userdata.Username {
		filedata_decrypted, _ := userlib.PKEDec(userdata.SharedKeys[retrieve.MetaLocationAsUUID], tmp_encrypted_filedata)
		ok2 := json.Unmarshal(filedata_decrypted, &file)
		if ok2 != nil {
			return nil, errors.New("unmarshall errorTres")
		}
		dataBytes = file.Data

		return dataBytes, nil
	}

	filedata_decrypted, _ := userlib.PKEDec(userdata.PrivateKey, tmp_encrypted_filedata)
	ok2 := json.Unmarshal(filedata_decrypted, &file)
	if ok2 != nil {
		return nil, errors.New("unmarshall error2")
	}

	dataBytes = file.Data

	return dataBytes, nil
}

//TODO: This is a toy implementation.
// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
// dataJSON, ok := userlib.DatastoreGet(storageKey)
// if !ok {
// 	return nil, errors.New(strings.ToTitle("File not found!"))
// }
// json.Unmarshal(dataJSON, &dataBytes)
// return dataBytes, nil
//End of toy implementation

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html

//appending pk and []byte
type SharedData struct {
	// PrivKey         userlib.PrivateKeyType
	Shared_metahmac []byte
	FileSymKey      []byte
}

//prove authentic shares
type SharedIntegrity struct {
	DSVerifier     userlib.DSVerifyKey
	MetaLocation   []byte
	SharedSigned   []byte
	SharedUnsigned []byte
	PrivKey        userlib.PrivateKeyType
}

func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	recipient_pubKey, valid := userlib.KeystoreGet(recipient)
	if !valid {
		return accessToken, errors.New("no such user")
	}

	//prepping private key for decryption and also meta hmac for verification
	fileData := userdata.UserFiles[filename]
	ToShare := SharedData{fileData.FileHashKey, fileData.FileSymKey}

	//marshalling keys to be encrypted
	ToShare_marshal, _ := json.Marshal(ToShare)
	// return accessToken, errors.New(strconv.Itoa(len(ToShare_marshal)))

	//encrypting with recipient public key
	EncryptedData, err := userlib.PKEEnc(recipient_pubKey, ToShare_marshal)
	Signed_Encrypted_Data, _ := userlib.DSSign(userdata.DSSigner, EncryptedData)

	// return accessToken, errors.New("checkpoint1")

	//prove authentic by putting share action in datastore
	accessToken = uuid.New()
	current_user, _ := userlib.PKEDec(userdata.PrivateKey, fileData.Owner)
	if string(current_user) != userdata.Username {
		shareVectorNotOwner := SharedIntegrity{userdata.DSVerifier, []byte(fileData.MetaDS), Signed_Encrypted_Data, EncryptedData, userdata.SharedKeys[fileData.MetaLocationAsUUID]}
		shareVector_marshal_not_Owner, _ := json.Marshal(shareVectorNotOwner)
		userlib.DatastoreSet(accessToken, shareVector_marshal_not_Owner)
		return accessToken, err
	}

	shareVector := SharedIntegrity{userdata.DSVerifier, []byte(fileData.MetaDS), Signed_Encrypted_Data, EncryptedData, userdata.PrivateKey}
	shareVector_marshal, _ := json.Marshal(shareVector)

	// return accessToken, errors.New("checkpoint2")

	userlib.DatastoreSet(accessToken, shareVector_marshal)

	// return accessToken, errors.New("checkpoint3")

	return accessToken, err
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {

	var SharedData_Unmarshal SharedIntegrity
	var SharedData_Unencrypted_Unmarshaled SharedData

	sender_pubkey, valid := userlib.KeystoreGet(sender)
	if !valid {
		return errors.New("no sender")
	}

	SharedData_Marshal, valid := userlib.DatastoreGet(accessToken)
	if !valid {
		return errors.New("no valid UUID")
	}

	ok := json.Unmarshal(SharedData_Marshal, &SharedData_Unmarshal)
	if ok != nil {
		return errors.New("unmarshal error")
	}

	ok = userlib.DSVerify(SharedData_Unmarshal.DSVerifier, SharedData_Unmarshal.SharedUnsigned, SharedData_Unmarshal.SharedSigned)
	if ok != nil {
		return errors.New("signature corrupted")
	}

	SharedData_Unencrypted, _ := userlib.PKEDec(userdata.PrivateKey, SharedData_Unmarshal.SharedUnsigned)

	ok = json.Unmarshal(SharedData_Unencrypted, &SharedData_Unencrypted_Unmarshaled)
	if ok != nil {
		return errors.New("unmarshal error")
	}

	owner, _ := userlib.PKEEnc(sender_pubkey, []byte(sender))
	metaLocationasUUID := bytesToUUID(SharedData_Unmarshal.MetaLocation)
	userdata.UserFiles[filename] = FilesStruct{owner, metaLocationasUUID, SharedData_Unencrypted_Unmarshaled.Shared_metahmac, SharedData_Unencrypted_Unmarshaled.FileSymKey, string(SharedData_Unmarshal.MetaLocation)}

	//updating userdata
	userdata.SharedKeys[metaLocationasUUID] = SharedData_Unmarshal.PrivKey

	//marshalling userdata and making iv
	marshal_data, _ := json.Marshal(userdata)
	iv := make([]byte, userlib.AESBlockSizeBytes+len(marshal_data))
	iv = iv[:userlib.AESBlockSizeBytes]
	copy(iv, userlib.RandomBytes(16))

	//encrypting userdata
	padded_marshal := SymEncPadder(marshal_data)
	userdata_encrypted := userlib.SymEnc(userdata.RSAKey, iv, padded_marshal)

	//Hashes the encrypted data using hashkey
	userdata_hmac, _ := userlib.HashKDF(userdata.HashKey, userdata_encrypted)

	//store encrypted and hashed data appended
	userdata_cipher := append(userdata_encrypted, userdata_hmac...)

	//store userdata in datastore using digital signature (from username)
	userdata_uuid := bytesToUUID(userdata.DigitalSignatureKey)
	userlib.DatastoreSet(userdata_uuid, userdata_cipher)

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	var Metadata MetaData

	//retrieve files from user
	retrieve := userdata.UserFiles[filename]
	metadata_cipher, valid := userlib.DatastoreGet(retrieve.MetaLocationAsUUID)

	if !valid {
		return errors.New("no such file")
	}

	current_user, _ := userlib.PKEDec(userdata.PrivateKey, retrieve.Owner)
	if string(current_user) != userdata.Username {
		return errors.New("not the owner")
	}

	//separated cipher "unappending"
	tmp_encrypted := metadata_cipher[:(len(metadata_cipher) - userlib.AESKeySizeBytes)]
	tmp_hmac := metadata_cipher[(len(metadata_cipher) - userlib.AESKeySizeBytes):]

	//is the hmac untouched "has the encrypted data been changed"
	generated_tmp_hmac, _ := userlib.HashKDF(retrieve.FileHashKey, tmp_encrypted)
	if !userlib.HMACEqual(tmp_hmac, generated_tmp_hmac) {
		return errors.New("data has no integrity")
	}

	//unecrypt metadata
	tmp_metadata := userlib.SymDec(retrieve.FileSymKey, tmp_encrypted)
	tmp_metadata = SymDecUnpad(tmp_metadata)
	ok := json.Unmarshal(tmp_metadata, &Metadata)
	if ok != nil {
		return errors.New("unmarshall error")
	}

	//make new encryption settings
	fileSymKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.AESBlockSizeBytes))
	fileHashKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.AESKeySizeBytes))

	//marshalling metadata and making jv
	meta_marshal, _ := json.Marshal(Metadata)
	jv := make([]byte, userlib.AESBlockSizeBytes+len(meta_marshal))
	jv = jv[:userlib.AESBlockSizeBytes]
	copy(jv, userlib.RandomBytes(16))

	//encrypting metadata with file symmetric key
	padded_marshal := SymEncPadder(meta_marshal)
	metadata_encrypted := userlib.SymEnc(fileSymKey, jv, padded_marshal)

	//Hashes the encrypted data using hashkey
	meta_hmac, _ := userlib.HashKDF(fileHashKey, metadata_encrypted)

	//store encrypted and hashed data appended
	metadata_cipher = append(metadata_encrypted, meta_hmac...)

	//get new uuid, hide metadata
	TheUUIDasString := uuid.New().String()
	TheUUID := bytesToUUID([]byte(TheUUIDasString))

	//update datastore
	userlib.DatastoreDelete(retrieve.MetaLocationAsUUID)
	userlib.DatastoreSet(TheUUID, metadata_cipher)

	//update UserFiles
	userdata.UserFiles[filename] = FilesStruct{retrieve.Owner, TheUUID, meta_hmac, fileSymKey, userdata.UserFiles[filename].MetaDS}

	//retrieve file data
	filedata_cipher, valid := userlib.DatastoreGet(Metadata.FileDSKeyAsUUID)

	if !valid {
		return errors.New("no file")
	}

	//separated cipher "unappending"
	tmp_encrypted = filedata_cipher[:(len(filedata_cipher) - userlib.AESKeySizeBytes)]
	tmp_hmac = filedata_cipher[(len(filedata_cipher) - userlib.AESKeySizeBytes):]

	//is the hmac untouched "has the encrypted data been changed"
	generated_tmp_hmac, _ = userlib.HashKDF(Metadata.File_hmac, tmp_encrypted)
	if !userlib.HMACEqual(tmp_hmac, generated_tmp_hmac) {
		return errors.New("data has no integrity")
	}

	//Hashes the encrypted data using hashkey
	file_hmac, _ := userlib.HashKDF(fileHashKey, tmp_encrypted)

	//store encrypted and hashed data appended
	file_cipher := append(tmp_encrypted, file_hmac...)

	//store file in datastore using digital signature
	//hide it also from the scary people

	userlib.DatastoreDelete(Metadata.FileDSKeyAsUUID)
	fileDSKey := userlib.Argon2Key([]byte(retrieve.MetaDS), userlib.RandomBytes(36), uint32(len(retrieve.MetaDS)))
	file_uuid := bytesToUUID([]byte(fileDSKey))
	userlib.DatastoreSet(file_uuid, file_cipher)

	//updating userdata

	//marshalling userdata and making iv
	marshal_data, _ := json.Marshal(userdata)
	iv := make([]byte, userlib.AESBlockSizeBytes+len(marshal_data))
	iv = iv[:userlib.AESBlockSizeBytes]
	copy(iv, userlib.RandomBytes(16))

	//encrypting userdata
	padded_marshal_data := SymEncPadder(marshal_data)
	userdata_encrypted := userlib.SymEnc(userdata.RSAKey, iv, padded_marshal_data)

	//Hashes the encrypted data using hashkey
	userdata_hmac, _ := userlib.HashKDF(userdata.HashKey, userdata_encrypted)

	//store encrypted and hashed data appended
	userdata_cipher := append(userdata_encrypted, userdata_hmac...)

	//store userdata in datastore using digital signature (from username)
	userdata_uuid := bytesToUUID(userdata.DigitalSignatureKey)
	userlib.DatastoreSet(userdata_uuid, userdata_cipher)

	return err
}
