package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &JwkFromK8sDataSource{}

type JwkFromK8sDataSource struct{}

type JwkFromK8sDataSourceModel struct {
	ClientCertificate    types.String `tfsdk:"client_certificate"`
	ClientKey            types.String `tfsdk:"client_key"`
	ClusterCACertificate types.String `tfsdk:"cluster_ca_certificate"`
	Host                 types.String `tfsdk:"host"`
	Id                   types.String `tfsdk:"id"`
	Jwks                 types.List   `tfsdk:"jwks"`
}

type JwksResp struct {
	Keys []json.RawMessage `json:"keys"`
}

func NewJwkFromK8sDataSource() datasource.DataSource {
	return &JwkFromK8sDataSource{}
}

func (d *JwkFromK8sDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_from_k8s"
}

func (d *JwkFromK8sDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This data source can be used to fetcks JWKs from a K8S cluster",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "ID",
				Computed:            true,
			},
			"client_certificate": schema.StringAttribute{
				MarkdownDescription: "K8S Client Certificate",
				Required:            true,
			},
			"client_key": schema.StringAttribute{
				MarkdownDescription: "K8S Client Key",
				Required:            true,
			},
			"cluster_ca_certificate": schema.StringAttribute{
				MarkdownDescription: "K8S Cluster Certificate",
				Required:            true,
			},
			"host": schema.StringAttribute{
				MarkdownDescription: "K8S Host",
				Required:            true,
			},
			"jwks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of JWKs",
				Computed:            true,
			},
		},
	}
}

func (d *JwkFromK8sDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
}

func (d *JwkFromK8sDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data JwkFromK8sDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	clientCertStr := data.ClientCertificate.ValueString()
	clientKeyStr := data.ClientKey.ValueString()
	cert, err := tls.X509KeyPair([]byte(clientCertStr), []byte(clientKeyStr))
	if err != nil {
		resp.Diagnostics.AddError("X509KeyPair", fmt.Sprintf("Can't create X509: %s", err))
		return
	}

	clusterCAStr := data.ClusterCACertificate.ValueString()
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(clusterCAStr)); !ok {
		resp.Diagnostics.AddError("AppendCertsFromPEM", "Can't load cluster CA")
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	host := strings.TrimRight(data.Host.ValueString(), "/")
	k8sResp, err := client.Get(host + "/openid/v1/jwks")
	if err != nil {
		resp.Diagnostics.AddError("Get", fmt.Sprintf("Fail to query K8S cluster : %s", err))
		return
	}
	defer k8sResp.Body.Close()

	jwksData, err := io.ReadAll(k8sResp.Body)
	if err != nil {
		resp.Diagnostics.AddError("ReadAll", fmt.Sprintf("Fail to read resp : %s", err))
		return
	}

	var jwksResp JwksResp
	err = json.Unmarshal(jwksData, &jwksResp)
	if err != nil {
		resp.Diagnostics.AddError("Unmarshal", fmt.Sprintf("Can't unmarshal JwksResp : %s", err))
		return
	}

	var jwksAttr []attr.Value
	for _, jwkRaw := range jwksResp.Keys {
		jwk, err := json.Marshal(&jwkRaw)
		if err != nil {
			resp.Diagnostics.AddError("Marshal", fmt.Sprintf("Can't marshal jwkRaw : %s", err))
			return
		}
		jwksAttr = append(jwksAttr, types.StringValue(string(jwk)))
	}

	data.Id = types.StringValue(host)
	data.Jwks, _ = types.ListValue(types.StringType, jwksAttr)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
