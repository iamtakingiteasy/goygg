package ygg

type serverTextureMetadata struct {
	Model string `json:"model"`
}

type serverTexture struct {
	URL      string                 `json:"url"`
	Metadata *serverTextureMetadata `json:"metadata,omitempty"`
}

type serverProfilePropertyTexturesDetails struct {
	Skin *serverTexture `json:"SKIN,omitempty"`
	Cape *serverTexture `json:"CAPE,omitempty"`
}

type serverProfilePropertyTextures struct {
	ProfileID   string                                `json:"profileId"`
	ProfileName string                                `json:"profileName"`
	Textures    *serverProfilePropertyTexturesDetails `json:"textures"`
	Timestamp   int64                                 `json:"timestamp"`
}

type serverProfileProperty struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
}

type serverProfile struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Properties []*serverProfileProperty `json:"properties,omitempty"`
}

type serverUser struct {
	ID         string        `json:"id"`
	Properties []interface{} `json:"properties"`
}
