package scim

import (
	"time"
)

const (
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// SCIMName represents structured name components.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// SCIMMultiValued represents email, role, phone, or group items.
type SCIMMultiValued struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMMeta holds resource metadata.
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// SCIMUser represents an RFC 7643 User Resource.
type SCIMUser struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId,omitempty"`
	UserName    string            `json:"userName"`
	Name        *SCIMName         `json:"name,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	Active      bool              `json:"active"`
	Emails      []SCIMMultiValued `json:"emails,omitempty"`
	Roles       []SCIMMultiValued `json:"roles,omitempty"`
	Groups      []SCIMMultiValued `json:"groups,omitempty"`
	Meta        SCIMMeta          `json:"meta"`
}

// SCIMGroup represents an RFC 7643 Group Resource.
type SCIMGroup struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []SCIMMultiValued `json:"members,omitempty"`
	Meta        SCIMMeta          `json:"meta"`
}

// ListResponse encapsulates pagination for SCIM collections.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// ErrorResponse represents an RFC 7644 Error message.
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// PatchOperation represents a single operation in a PATCH request.
type PatchOperation struct {
	Op    string `json:"op"` // "add", "replace", "remove"
	Path  string `json:"path,omitempty"`
	Value any    `json:"value"`
}

// PatchRequest represents an RFC 7644 PATCH payload.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}
