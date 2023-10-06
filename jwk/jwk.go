package jwk

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		DataSourcesMap: map[string]*schema.Resource{
			"jwk_to_pem": datasourceJwkToPem(),
		},
	}
}

func datasourceJwkToPem() *schema.Resource {
	return &schema.Resource{
		Description:        "This data source can be used to convert a jwk to PEM format",
		ReadWithoutTimeout: datasourceJwkToPemRead,
		Schema: map[string]*schema.Schema{
			"jwk": {
				Type:     schema.TypeString,
				Required: true,
			},
			"pem": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func datasourceJwkToPemRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	jwkStr := d.Get("jwk").(string)

	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON([]byte(jwkStr))
	if err != nil {
		return diag.FromErr(err)
	}

	pubData, err := x509.MarshalPKIXPublicKey(jwk.Key)
	if err != nil {
		return diag.FromErr(err)
	}

	var pemData bytes.Buffer
	err = pem.Encode(&pemData, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubData,
	})
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(jwk.KeyID)
	err = d.Set("pem", pemData.String())
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}
