package sso

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// SAMLServiceProvider generates standard SP metadata and processes basic assertions.
type SAMLServiceProvider struct {
	EntityID string
	ACSURL   string
}

func NewSAMLServiceProvider(entityID, acsURL string) *SAMLServiceProvider {
	return &SAMLServiceProvider{
		EntityID: entityID,
		ACSURL:   acsURL,
	}
}

// GenerateMetadata returns the SAML 2.0 XML metadata for this Service Provider.
func (s *SAMLServiceProvider) GenerateMetadata() string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`, s.EntityID, s.ACSURL)
}

// ParseSAMLResponse extracts user identity and email from a base64-encoded SAMLResponse payload.
func (s *SAMLServiceProvider) ParseSAMLResponse(samlResponseB64 string) (*IdentityClaims, error) {
	xmlData, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, errors.New("invalid base64 in SAMLResponse")
	}

	type Attribute struct {
		Name   string   `xml:"Name,attr"`
		Values []string `xml:"AttributeValue"`
	}

	type Subject struct {
		NameID string `xml:"NameID"`
	}

	type Assertion struct {
		Subject    Subject     `xml:"Subject"`
		Attributes []Attribute `xml:"AttributeStatement>Attribute"`
	}

	type Response struct {
		XMLName   xml.Name  `xml:"Response"`
		Assertion Assertion `xml:"Assertion"`
	}

	var resp Response
	if err := xml.Unmarshal(xmlData, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse SAML XML: %w", err)
	}

	nameID := strings.TrimSpace(resp.Assertion.Subject.NameID)
	if nameID == "" {
		return nil, errors.New("missing NameID in SAML assertion")
	}

	claims := &IdentityClaims{
		Subject:           nameID,
		Email:             nameID,
		PreferredUsername: nameID,
		Provider:          "saml",
	}

	for _, attr := range resp.Assertion.Attributes {
		name := strings.ToLower(attr.Name)
		val := ""
		if len(attr.Values) > 0 {
			val = strings.TrimSpace(attr.Values[0])
		}

		if strings.Contains(name, "email") || strings.Contains(name, "mail") {
			claims.Email = val
		} else if strings.Contains(name, "displayname") || strings.Contains(name, "name") {
			claims.Name = val
		} else if strings.Contains(name, "username") || strings.Contains(name, "uid") {
			claims.PreferredUsername = val
		} else if strings.Contains(name, "role") {
			claims.Role = val
		}
	}

	return claims, nil
}
