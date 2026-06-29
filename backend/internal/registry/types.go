package registry

type CatalogResponse struct {
	Repositories []string `json:"repositories"`
	NextLast     string   `json:"nextLast,omitempty"`
	Link         string   `json:"link,omitempty"`
}

type TagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type ManifestResponse struct {
	Name         string       `json:"name"`
	Reference    string       `json:"reference"`
	Digest       string       `json:"digest,omitempty"`
	ContentType  string       `json:"contentType,omitempty"`
	Manifest     interface{}  `json:"manifest"`
	ArtifactType string       `json:"artifactType,omitempty"`
	Config       *ImageConfig `json:"config,omitempty"`
	SharedTags   []string     `json:"sharedTags,omitempty"`
}

type ImageConfig struct {
	Created      string            `json:"created,omitempty"`
	Entrypoint   []string          `json:"entrypoint,omitempty"`
	Cmd          []string          `json:"cmd,omitempty"`
	Env          []string          `json:"env,omitempty"`
	Ports        []string          `json:"ports,omitempty"`
	Volumes      []string          `json:"volumes,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	WorkingDir   string            `json:"workingDir,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	OS           string            `json:"os,omitempty"`
}

type RawManifest struct {
	Name        string
	Reference   string
	Digest      string
	ContentType string
	Body        []byte
	Payload     interface{}
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
