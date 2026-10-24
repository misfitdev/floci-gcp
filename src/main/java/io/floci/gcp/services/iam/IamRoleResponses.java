package io.floci.gcp.services.iam;

import io.floci.gcp.core.common.GcpException;
import jakarta.ws.rs.core.Response;

import java.util.LinkedHashMap;
import java.util.Map;

/** Request-body handling shared by the project and organization role controllers. */
final class IamRoleResponses {

    private IamRoleResponses() {}

    @SuppressWarnings("unchecked")
    static Response create(IamRoleService service, String parent, Map<String, Object> body) {
        Map<String, Object> request = body != null ? body : Map.of();
        Object roleId = request.get("roleId");
        Object role = request.get("role");
        if (roleId != null && !(roleId instanceof String)) {
            throw GcpException.invalidArgument("Invalid value for roleId");
        }
        if (role != null && !(role instanceof Map<?, ?>)) {
            throw GcpException.invalidArgument("Invalid value for role");
        }
        return Response.ok(service.create(parent, (String) roleId, (Map<String, Object>) role)).build();
    }

    static Response list(IamRoleService service, String parent, String view, boolean showDeleted,
            int pageSize, String pageToken) {
        IamRoleService.RolePage page = service.list(parent, view, showDeleted, pageSize, pageToken);
        Map<String, Object> response = new LinkedHashMap<>();
        if (!page.roles().isEmpty()) {
            response.put("roles", page.roles());
        }
        if (page.nextPageToken() != null) {
            response.put("nextPageToken", page.nextPageToken());
        }
        return Response.ok(response).build();
    }

    static Response undelete(IamRoleService service, String name, Map<String, Object> body) {
        Object etag = body != null ? body.get("etag") : null;
        return Response.ok(service.undelete(name, etag != null ? etag.toString() : null)).build();
    }
}
