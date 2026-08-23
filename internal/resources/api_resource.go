package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Trozz/terraform-provider-pocketid/internal/client"
)

var (
	_ resource.Resource                = &apiResource{}
	_ resource.ResourceWithConfigure   = &apiResource{}
	_ resource.ResourceWithImportState = &apiResource{}
)

// NewAPIResource creates the resource implementation for Pocket-ID protected
// API resources.
func NewAPIResource() resource.Resource {
	return &apiResource{}
}

type apiResource struct {
	client *client.Client
}

type apiResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Resource      types.String `tfsdk:"resource"`
	Permissions   types.Set    `tfsdk:"permissions"`
	PermissionIDs types.Map    `tfsdk:"permission_ids"`
}

type apiPermissionModel struct {
	Key         types.String `tfsdk:"key"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

var apiPermissionAttrTypes = map[string]attr.Type{
	"key":         types.StringType,
	"name":        types.StringType,
	"description": types.StringType,
}

// Metadata returns the resource type name.
func (r *apiResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api"
}

// Schema defines the API resource schema.
func (r *apiResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a protected API resource and its permissions in Pocket-ID.",
		MarkdownDescription: `Manages a protected API resource and its permissions in Pocket-ID.

API resources define the OAuth 2.0 audience and scopes that a client may request. The resource identifier is immutable because changing it would invalidate existing tokens. permission_ids maps each declared permission key to the Pocket-ID permission ID for use with pocketid_api_client_access.`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The Pocket-ID API resource ID.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The display name of the API resource.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 50),
				},
			},
			"resource": schema.StringAttribute{
				Description: "The immutable OAuth 2.0 resource indicator (audience) for this API.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 350),
				},
			},
			"permissions": schema.SetNestedAttribute{
				Description: "The complete set of permissions (scopes) declared by this API. Removing an entry revokes that permission from all API clients.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key": schema.StringAttribute{
							Description: "The permission scope key, unique within this API.",
							Required:    true,
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 128),
							},
						},
						"name": schema.StringAttribute{
							Description: "The human-readable permission name.",
							Required:    true,
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 50),
							},
						},
						"description": schema.StringAttribute{
							Description: "An optional permission description.",
							Optional:    true,
							Validators: []validator.String{
								stringvalidator.LengthAtMost(200),
							},
						},
					},
				},
			},
			"permission_ids": schema.MapAttribute{
				Description: "A computed map from permission key to Pocket-ID permission ID.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *apiResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = c
}

// Create creates the API and replaces its permission declaration.
func (r *apiResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	permissions, diags := apiPermissionsToRequest(ctx, plan.Permissions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateAPI(&client.APICreateRequest{
		Name:     plan.Name.ValueString(),
		Resource: plan.Resource.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error creating API resource", "Could not create API resource, unexpected error: "+err.Error())
		return
	}

	updated, err := r.client.UpdateAPIPermissions(created.ID, permissions)
	if err != nil {
		_ = r.client.DeleteAPI(created.ID)
		resp.Diagnostics.AddError("Error declaring API permissions", "Could not declare API permissions; the newly-created API resource was deleted. Error: "+err.Error())
		return
	}

	resp.Diagnostics.Append(apiToModel(ctx, updated, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the current Pocket-ID API resource.
func (r *apiResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api, err := r.client.GetAPI(state.ID.ValueString())
	if err != nil {
		if isNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading API resource", "Could not read API resource ID "+state.ID.ValueString()+": "+err.Error())
		return
	}

	resp.Diagnostics.Append(apiToModel(ctx, api, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update changes the API name and, when necessary, replaces its permission declaration.
func (r *apiResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state apiResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := &client.API{ID: state.ID.ValueString()}
	if !plan.Name.Equal(state.Name) {
		updated, err := r.client.UpdateAPI(state.ID.ValueString(), &client.APIUpdateRequest{Name: plan.Name.ValueString()})
		if err != nil {
			resp.Diagnostics.AddError("Error updating API resource", "Could not update API resource, unexpected error: "+err.Error())
			return
		}
		api = updated
	}

	if !plan.Permissions.Equal(state.Permissions) {
		permissions, diags := apiPermissionsToRequest(ctx, plan.Permissions)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		updated, err := r.client.UpdateAPIPermissions(state.ID.ValueString(), permissions)
		if err != nil {
			resp.Diagnostics.AddError("Error updating API permissions", "Could not update API permissions, unexpected error: "+err.Error())
			return
		}
		api = updated
	}

	// A no-op update is uncommon, but a current API response is still needed
	// to preserve every computed value.
	if api.Name == "" {
		current, err := r.client.GetAPI(state.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Error reading API resource", "Could not read API resource after update: "+err.Error())
			return
		}
		api = current
	}

	resp.Diagnostics.Append(apiToModel(ctx, api, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the API resource. A resource already deleted outside Terraform
// is treated as successfully removed.
func (r *apiResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting API resource", map[string]any{"id": state.ID.ValueString()})
	if err := r.client.DeleteAPI(state.ID.ValueString()); err != nil && !isNotFoundError(err) {
		resp.Diagnostics.AddError("Error deleting API resource", "Could not delete API resource, unexpected error: "+err.Error())
	}
}

// ImportState imports an API resource by Pocket-ID API resource ID.
func (r *apiResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func apiPermissionsToRequest(ctx context.Context, permissions types.Set) ([]client.APIPermissionInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	var models []apiPermissionModel
	if permissions.IsNull() || permissions.IsUnknown() {
		return []client.APIPermissionInput{}, diags
	}

	diags.Append(permissions.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return nil, diags
	}

	result := make([]client.APIPermissionInput, 0, len(models))
	for _, permission := range models {
		input := client.APIPermissionInput{
			Key:  permission.Key.ValueString(),
			Name: permission.Name.ValueString(),
		}
		if !permission.Description.IsNull() && !permission.Description.IsUnknown() {
			description := permission.Description.ValueString()
			input.Description = &description
		}
		result = append(result, input)
	}
	return result, diags
}

func apiToModel(ctx context.Context, api *client.API, model *apiResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	model.ID = types.StringValue(api.ID)
	model.Name = types.StringValue(api.Name)
	model.Resource = types.StringValue(api.Resource)

	permissions := make([]apiPermissionModel, 0, len(api.Permissions))
	permissionIDs := make(map[string]string, len(api.Permissions))
	for _, permission := range api.Permissions {
		description := types.StringNull()
		if permission.Description != nil {
			description = types.StringValue(*permission.Description)
		}
		permissions = append(permissions, apiPermissionModel{
			Key:         types.StringValue(permission.Key),
			Name:        types.StringValue(permission.Name),
			Description: description,
		})
		permissionIDs[permission.Key] = permission.ID
	}

	permissionSet, setDiags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: apiPermissionAttrTypes}, permissions)
	diags.Append(setDiags...)
	model.Permissions = permissionSet

	permissionIDMap, mapDiags := types.MapValueFrom(ctx, types.StringType, permissionIDs)
	diags.Append(mapDiags...)
	model.PermissionIDs = permissionIDMap
	return diags
}

func isNotFoundError(err error) bool {
	return strings.Contains(err.Error(), "HTTP 404")
}
