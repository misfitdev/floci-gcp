package io.floci.gcp.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.gcp.core.common.GcpException;
import io.floci.gcp.core.common.ProjectRegistry;
import io.floci.gcp.core.storage.InMemoryStorage;
import io.floci.gcp.services.iam.authorization.IamAuthorizationRegistry;
import io.floci.gcp.services.iam.authorization.IamOperation;
import io.floci.gcp.services.iam.authorization.IamPermissionCheck;
import jakarta.ws.rs.HttpMethod;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IamRoleAuthorizationServiceTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final IamRoleAuthorizationAdapter adapter = new IamRoleAuthorizationAdapter();

    @Test
    void everyRestHandlerIsInventoriedAndUnknownMethodsFailClosed() {
        Set<String> handlers = Set.of("create", "list", "get", "patch", "delete", "undelete");
        assertEquals(handlers, handlers(IamRolesController.class));
        assertEquals(handlers, handlers(IamOrganizationRolesController.class));
        assertThrows(GcpException.class, () -> adapter.restOperation("newHandler",
                Map.of("project", "p", "role", "r"), mapper.createObjectNode()));
        assertThrows(GcpException.class, () -> adapter.restOperation("get",
                Map.of("project", "p"), mapper.createObjectNode()));
        assertThrows(GcpException.class, () -> adapter.restOperation("get",
                Map.of("folder", "f", "role", "r"), mapper.createObjectNode()));
        assertThrows(GcpException.class, () -> adapter.checks(new IamOperation("GetIamPolicy", "projects/p/roles/r")));
        assertThrows(GcpException.class, () -> adapter.grpcOperation("GetRole", mapper.createObjectNode()));
        assertTrue(adapter.resource("projects/p").isEmpty());
        assertTrue(adapter.resource("organizations/1").isEmpty());
        assertTrue(adapter.resource("roles/viewer").isEmpty());
    }

    @Test
    void routesUseExactPermissionsAndTargets() {
        record Route(String method, String permission, boolean parentTarget) {}
        List<Route> routes = List.of(
                new Route("create", "iam.roles.create", true),
                new Route("list", "iam.roles.list", true),
                new Route("get", "iam.roles.get", false),
                new Route("patch", "iam.roles.update", false),
                new Route("delete", "iam.roles.delete", false),
                new Route("undelete", "iam.roles.undelete", false));
        for (Map<String, String> parent : List.of(Map.of("project", "p"), Map.of("organization", "42"))) {
            String parentName = parent.containsKey("project") ? "projects/p" : "organizations/42";
            for (Route route : routes) {
                Map<String, String> path = new HashMap<>(parent);
                if (!route.parentTarget()) {
                    path.put("role", "reader");
                }
                IamOperation operation = adapter.restOperation(route.method(), path, mapper.createObjectNode());
                List<IamPermissionCheck> checks = adapter.checks(operation);
                assertEquals(1, checks.size());
                IamPermissionCheck check = checks.getFirst();
                assertEquals(route.permission(), check.permission(), route.toString());
                assertEquals(route.parentTarget() ? parentName : parentName + "/roles/reader",
                        check.resource().name(), route.toString());
                assertEquals(parentName, check.resource().policyResource(), route.toString());
                if (!route.parentTarget()) {
                    assertEquals("iam.googleapis.com/Role", check.resource().type());
                }
            }
        }
    }

    @Test
    void roleSlicesMatchUpstreamAndBasicRolesGrantNoRoleManagement() {
        IamRoleCatalog roles = new IamRoleCatalog(new IamAuthorizationRegistry(List.of(adapter)));
        Set<String> management = Set.of("iam.roles.create", "iam.roles.delete", "iam.roles.get",
                "iam.roles.list", "iam.roles.undelete", "iam.roles.update");
        for (String admin : List.of("roles/iam.roleAdmin", "roles/iam.organizationRoleAdmin")) {
            for (String permission : management) {
                assertTrue(roles.grants(admin, permission), admin + " " + permission);
            }
        }
        for (String viewer : List.of("roles/iam.roleViewer", "roles/iam.organizationRoleViewer")) {
            assertTrue(roles.grants(viewer, "iam.roles.get"));
            assertTrue(roles.grants(viewer, "iam.roles.list"));
            assertFalse(roles.grants(viewer, "iam.roles.create"));
            assertFalse(roles.grants(viewer, "iam.roles.update"));
        }
        for (String basic : List.of("roles/owner", "roles/editor", "roles/viewer")) {
            for (String permission : management) {
                assertFalse(roles.grants(basic, permission), basic + " " + permission);
            }
        }
    }

    @Test
    void catalogResolvesCustomRolesOnlyWithinTheirPolicyScope() {
        ProjectRegistry projects = mock(ProjectRegistry.class);
        when(projects.find(anyString())).thenReturn(Optional.empty());
        IamRoleService customRoles = new IamRoleService(new InMemoryStorage<>(), projects);
        customRoles.create("projects/p", "reader", Map.of("includedPermissions", List.of("pubsub.topics.get")));
        IamRoleCatalog roles = new IamRoleCatalog(new IamAuthorizationRegistry(List.of(adapter)), customRoles);

        assertTrue(roles.contains("projects/p/roles/reader", "projects/p/topics/t"));
        assertTrue(roles.grants("projects/p/roles/reader", "pubsub.topics.get", "projects/p/topics/t"));
        assertFalse(roles.grants("projects/p/roles/reader", "pubsub.topics.delete", "projects/p/topics/t"));
        assertFalse(roles.contains("projects/p/roles/reader", "projects/q"));
        assertFalse(roles.grants("projects/p/roles/reader", "pubsub.topics.get", "projects/q"));
        assertFalse(roles.grants("projects/p/roles/reader", "pubsub.topics.get"));
        assertTrue(roles.grants("roles/iam.roleViewer", "iam.roles.get", "projects/q"));
    }

    private Set<String> handlers(Class<?> controller) {
        return Arrays.stream(controller.getDeclaredMethods())
                .filter(method -> Arrays.stream(method.getAnnotations())
                        .anyMatch(annotation -> annotation.annotationType().isAnnotationPresent(HttpMethod.class)))
                .map(Method::getName).collect(Collectors.toSet());
    }
}
