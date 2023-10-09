package provider

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &JwkToPemDataSource{}

type JwkToPemDataSource struct{}

type JwkToPemDataSourceModel struct {
	Id  types.String `tfsdk:"id"`
	Jwk types.String `tfsdk:"jwk"`
	Pem types.String `tfsdk:"pem"`
}

func NewJwkToPemDataSource() datasource.DataSource {
	return &JwkToPemDataSource{}
}

func (d *JwkToPemDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_to_pem"
}

func (d *JwkToPemDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This data source can be used to convert a JWK to PEM format",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "ID",
				Computed:            true,
			},
			"jwk": schema.StringAttribute{
				MarkdownDescription: "JWK",
				Required:            true,
			},
			"pem": schema.StringAttribute{
				MarkdownDescription: "PEM",
				Computed:            true,
			},
		},
	}
}

func (d *JwkToPemDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
}

func (d *JwkToPemDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data JwkToPemDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	jwkStr := data.Jwk.ValueString()

	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON([]byte(jwkStr))
	if err != nil {
		resp.Diagnostics.AddError("UnmarshalJSON", fmt.Sprintf("Can't unmarshal JWK : %s", err))
		return
	}

	pubData, err := x509.MarshalPKIXPublicKey(jwk.Key)
	if err != nil {
		resp.Diagnostics.AddError("MarshalPKIXPublicKey", fmt.Sprintf("Fail to marshal key: %s", err))
		return
	}

	var pemData bytes.Buffer
	err = pem.Encode(&pemData, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubData,
	})
	if err != nil {
		resp.Diagnostics.AddError("Encode", fmt.Sprintf("Fail to encode PEM key: %s", err))
		return
	}

	data.Id = types.StringValue(jwk.KeyID)
	data.Pem = types.StringValue(strings.TrimSpace(pemData.String()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
