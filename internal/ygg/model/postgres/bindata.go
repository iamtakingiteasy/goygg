package postgres

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

func bindata_read(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	return buf.Bytes(), nil
}

var __1_initialize_down_sql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x4a\x29\xca\x2f\x50\x28\x49\x4c\xca\x49\x55\x28\xc9\xcf\x4e\xcd\x2b\xb6\xe6\x42\x12\x2a\x2d\x4e\x2d\x2a\xb6\x06\x04\x00\x00\xff\xff\x52\x06\x5d\x1b\x24\x00\x00\x00")

func _1_initialize_down_sql() ([]byte, error) {
	return bindata_read(
		__1_initialize_down_sql,
		"1_initialize.down.sql",
	)
}

var __1_initialize_up_sql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x91\x41\x6e\xc3\x30\x0c\x04\xef\x7a\x05\x6f\x89\x81\xfe\x20\x8f\x31\x58\x79\x03\x10\xa6\x24\x57\x24\x91\xe6\xf7\x85\x9b\x5e\x82\xd8\x2e\xa2\xab\x76\xc4\x15\x27\x77\xb0\x83\x9c\x3f\x15\x14\x86\x6e\x74\x4e\x44\x32\xd1\xde\x71\x7c\x3b\x2d\x5d\x0a\xf7\x3b\xcd\xb8\x7f\x24\x22\x14\x16\x3d\x88\xd7\xe6\x54\x43\x95\xa2\xca\x57\x60\x45\x16\x36\xbb\xb5\xbe\x35\xe7\x09\xf9\xcd\xf6\x76\x15\xc5\xb8\xd1\x6a\xf7\xf9\x3f\xa4\x72\xc1\x9b\xc8\x7a\x1f\x1d\xa3\xcd\x52\xc7\xe8\xfa\x82\x4c\xb8\x72\xa8\xd3\xe9\xb4\x8b\x95\x36\x41\xdf\xc2\x32\x2f\xf8\x67\x5a\x1a\x2e\x29\x3d\x09\xf3\x36\xa3\x3e\x8c\xad\xee\x1e\x0b\xda\x12\x94\x55\x50\xfd\xe8\xf7\x9c\x33\xcc\x8e\x12\x62\x16\x98\x46\x76\x72\x29\x30\xe7\xb2\xbc\xb6\xac\xed\x76\x1e\xd2\x70\xf9\x09\x00\x00\xff\xff\xf8\x66\x07\xbc\x58\x02\x00\x00")

func _1_initialize_up_sql() ([]byte, error) {
	return bindata_read(
		__1_initialize_up_sql,
		"1_initialize.up.sql",
	)
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		return f()
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() ([]byte, error){
	"1_initialize.down.sql": _1_initialize_down_sql,
	"1_initialize.up.sql":   _1_initialize_up_sql,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for name := range node.Children {
		rv = append(rv, name)
	}
	return rv, nil
}

type _bintree_t struct {
	Func     func() ([]byte, error)
	Children map[string]*_bintree_t
}

var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"1_initialize.down.sql": &_bintree_t{_1_initialize_down_sql, map[string]*_bintree_t{}},
	"1_initialize.up.sql":   &_bintree_t{_1_initialize_up_sql, map[string]*_bintree_t{}},
}}
