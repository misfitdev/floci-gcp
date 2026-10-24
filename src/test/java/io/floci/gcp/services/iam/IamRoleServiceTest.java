package io.floci.gcp.services.iam;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.gcp.core.common.GcpException;
import io.floci.gcp.core.common.ProjectRecord;
import io.floci.gcp.core.common.ProjectRegistry;
import io.floci.gcp.core.storage.InMemoryStorage;
import io.floci.gcp.core.storage.PersistentStorage;
import io.floci.gcp.services.iam.model.StoredRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IamRoleServiceTest {

    private static final String ROLE = "projects/p/roles/reader";
    private static final String ORG_ROLE = "organizations/42/roles/reader";

    private final Map<String, ProjectRecord> projectRecords = new HashMap<>();
    private ProjectRegistry projects;
    private IamRoleService service;

    @BeforeEach
    void setUp() {
        projects = mock(ProjectRegistry.class);
        when(projects.find(anyString())).thenAnswer(invocation ->
                Optional.ofNullable(projectRecords.get(invocation.<String>getArgument(0))));
        service = new IamRoleService(new InMemoryStorage<>(), projects);
    }

    @Test
    void createReturnsRoleWithEtagAndOmitsAlphaStageAndFalseDeleted() throws Exception {
        StoredRole created = service.create("projects/p", "reader", role("Reader", "pubsub.topics.get"));

        assertEquals(ROLE, created.getName());
        assertEquals(List.of("pubsub.topics.get"), created.getIncludedPermissions());
        assertNotNull(created.getEtag());
        Map<String, Object> json = new ObjectMapper().convertValue(created, new TypeReference<>() {});
        assertEquals(Set.of("name", "title", "includedPermissions", "etag"), json.keySet());

        StoredRole ga = service.create("organizations/42", "reader", Map.of("stage", "GA"));
        assertEquals("GA", ga.getStage());
        assertEquals(ORG_ROLE, ga.getName());
    }

    @Test
    void createValidatesRoleIdParentAndFieldsAndReservesExistingIds() {
        for (String roleId : List.of("ab", "a".repeat(65), "has-dash", "has/slash")) {
            assertStatus("INVALID_ARGUMENT", () -> service.create("projects/p", roleId, Map.of()));
        }
        for (String parent : List.of("projects/-", "folders/1", "projects")) {
            assertStatus("INVALID_ARGUMENT", () -> service.create(parent, "reader", Map.of()));
        }
        assertStatus("INVALID_ARGUMENT", () -> service.create("projects/p", "reader",
                Map.of("includedPermissions", List.of("pubsub.*"))));
        assertStatus("INVALID_ARGUMENT", () -> service.create("projects/p", "reader",
                Map.of("title", "t".repeat(101))));
        assertStatus("INVALID_ARGUMENT", () -> service.create("projects/p", "reader",
                Map.of("stage", "UNKNOWN")));

        service.create("projects/p", "reader", Map.of());
        assertStatus("ALREADY_EXISTS", () -> service.create("projects/p", "reader", Map.of()));
        service.delete(ROLE, null);
        assertStatus("ALREADY_EXISTS", () -> service.create("projects/p", "reader", Map.of()));
        assertStatus("NOT_FOUND", () -> service.get("projects/p/roles/missing"));
    }

    @Test
    void listUsesBasicViewByDefaultAndHidesDeletedRolesUnlessRequested() {
        service.create("projects/p", "a_role", role("A", "pubsub.topics.get"));
        service.create("projects/p", "b_role", role("B", "pubsub.topics.list"));
        service.create("projects/other", "c_role", role("C", "pubsub.topics.list"));
        service.delete("projects/p/roles/b_role", null);

        IamRoleService.RolePage basic = service.list("projects/p", null, false, 0, null);
        assertEquals(List.of("projects/p/roles/a_role"), basic.roles().stream().map(StoredRole::getName).toList());
        assertTrue(basic.roles().getFirst().getIncludedPermissions().isEmpty());

        IamRoleService.RolePage full = service.list("projects/p", "FULL", true, 1, null);
        assertEquals(List.of("pubsub.topics.get"), full.roles().getFirst().getIncludedPermissions());
        assertNotNull(full.nextPageToken());
        IamRoleService.RolePage next = service.list("projects/p", "FULL", true, 1, full.nextPageToken());
        assertEquals(Boolean.TRUE, next.roles().getFirst().getDeleted());
        assertNull(next.nextPageToken());
        assertStatus("INVALID_ARGUMENT", () -> service.list("projects/p", "PARTIAL", false, 0, null));
    }

    @Test
    void updateHonorsMaskAndEtagInEitherBase64Alphabet() {
        StoredRole created = service.create("projects/p", "reader", role("Reader", "pubsub.topics.get"));

        StoredRole masked = service.update(ROLE, Map.of("title", "Ignored", "description", "Applied",
                "etag", created.getEtag()), "description");
        assertEquals("Reader", masked.getTitle());
        assertEquals("Applied", masked.getDescription());
        assertNotEquals(created.getEtag(), masked.getEtag());

        assertStatus("ABORTED", () -> service.update(ROLE, Map.of("etag", created.getEtag()), "title"));
        assertStatus("INVALID_ARGUMENT", () -> service.update(ROLE, Map.of(), "name"));

        String urlSafe = Base64.getUrlEncoder().encodeToString(Base64.getDecoder().decode(masked.getEtag()));
        StoredRole unmasked = service.update(ROLE, Map.of("includedPermissions",
                List.of("pubsub.topics.list"), "etag", urlSafe), null);
        assertEquals(List.of("pubsub.topics.list"), unmasked.getIncludedPermissions());
        assertEquals("Reader", unmasked.getTitle());
    }

    @Test
    void deleteAndUndeleteToggleStateAndRejectInvalidTransitions() {
        StoredRole created = service.create("projects/p", "reader", Map.of());
        assertStatus("FAILED_PRECONDITION", () -> service.undelete(ROLE, null));
        assertStatus("ABORTED", () -> service.delete(ROLE, "AAAAAAAAAAA="));

        StoredRole deleted = service.delete(ROLE, created.getEtag());
        assertEquals(Boolean.TRUE, deleted.getDeleted());
        assertStatus("FAILED_PRECONDITION", () -> service.delete(ROLE, null));
        assertStatus("FAILED_PRECONDITION", () -> service.update(ROLE, Map.of("title", "x"), "title"));
        assertEquals(Boolean.TRUE, service.get(ROLE).getDeleted());

        StoredRole restored = service.undelete(ROLE, deleted.getEtag());
        assertNull(restored.getDeleted());
    }

    @Test
    void projectRolesGrantOnlyThroughPoliciesOfTheirProject() {
        service.create("projects/p", "reader", role("Reader", "pubsub.topics.get"));

        assertEquals(Set.of("pubsub.topics.get"), service.grantedPermissions(ROLE, "projects/p"));
        assertEquals(Set.of("pubsub.topics.get"), service.grantedPermissions(ROLE, "projects/p/topics/t"));
        for (String outside : List.of("projects/other", "projects/other/topics/t", "projects/-/serviceAccounts/x",
                "projects/_/buckets/b", "buckets/b", "organizations/42")) {
            assertTrue(service.grantedPermissions(ROLE, outside).isEmpty(), outside);
            assertFalse(service.applies(ROLE, outside), outside);
        }
        assertTrue(service.grantedPermissions("projects/p/roles/missing", "projects/p").isEmpty());
        assertTrue(service.grantedPermissions("roles/viewer", "projects/p").isEmpty());
    }

    @Test
    void organizationRolesRequireRecordedOrganizationAncestryAndFailClosedOtherwise() {
        service.create("organizations/42", "reader", role("Reader", "pubsub.topics.get"));
        projectRecords.put("in-org", project("in-org", "organization", "42"));
        projectRecords.put("other-org", project("other-org", "organization", "7"));
        projectRecords.put("in-folder", project("in-folder", "folder", "42"));
        projectRecords.put("no-parent", project("no-parent", null, null));

        assertEquals(Set.of("pubsub.topics.get"), service.grantedPermissions(ORG_ROLE, "organizations/42"));
        assertEquals(Set.of("pubsub.topics.get"), service.grantedPermissions(ORG_ROLE, "projects/in-org/topics/t"));
        for (String outside : List.of("organizations/7", "projects/other-org", "projects/in-folder",
                "projects/no-parent", "projects/unknown", "buckets/b")) {
            assertTrue(service.grantedPermissions(ORG_ROLE, outside).isEmpty(), outside);
        }
    }

    @Test
    void permissionEditsDisablingAndDeletionAffectSubsequentDecisions() {
        StoredRole created = service.create("projects/p", "reader", role("Reader", "pubsub.topics.get"));
        StoredRole edited = service.update(ROLE, Map.of("includedPermissions", List.of("pubsub.topics.list")),
                "includedPermissions");
        assertEquals(Set.of("pubsub.topics.list"), service.grantedPermissions(ROLE, "projects/p"));

        StoredRole disabled = service.update(ROLE, Map.of("stage", "DISABLED"), "stage");
        assertTrue(service.grantedPermissions(ROLE, "projects/p").isEmpty());
        assertFalse(service.applies(ROLE, "projects/p"));
        service.update(ROLE, Map.of("stage", "GA", "etag", disabled.getEtag()), "stage");
        assertTrue(service.applies(ROLE, "projects/p"));

        service.delete(ROLE, null);
        assertTrue(service.grantedPermissions(ROLE, "projects/p").isEmpty());
        service.undelete(ROLE, null);
        assertEquals(Set.of("pubsub.topics.list"), service.grantedPermissions(ROLE, "projects/p"));
        assertNotEquals(created.getEtag(), edited.getEtag());
    }

    @Test
    void definitionsAndRevocationStatePersistAcrossRestart(@TempDir Path directory) {
        Path file = directory.resolve("iam-roles.json");
        PersistentStorage<String, StoredRole> store = new PersistentStorage<>(file, new TypeReference<>() {});
        store.load();
        IamRoleService first = new IamRoleService(store, projects);
        first.create("projects/p", "reader", role("Reader", "pubsub.topics.get"));
        first.create("projects/p", "revoked", role("Revoked", "pubsub.topics.get"));
        first.delete("projects/p/roles/revoked", null);
        first.create("projects/p", "disabled", Map.of("includedPermissions", List.of("pubsub.topics.get"),
                "stage", "DISABLED"));

        PersistentStorage<String, StoredRole> reloaded = new PersistentStorage<>(file, new TypeReference<>() {});
        reloaded.load();
        IamRoleService restarted = new IamRoleService(reloaded, projects);

        assertEquals(Set.of("pubsub.topics.get"), restarted.grantedPermissions(ROLE, "projects/p"));
        assertEquals(Boolean.TRUE, restarted.get("projects/p/roles/revoked").getDeleted());
        assertTrue(restarted.grantedPermissions("projects/p/roles/revoked", "projects/p").isEmpty());
        assertEquals("DISABLED", restarted.get("projects/p/roles/disabled").getStage());
        assertTrue(restarted.grantedPermissions("projects/p/roles/disabled", "projects/p").isEmpty());
    }

    @Test
    void concurrentUpdateWithStaleEtagCannotOverwriteADeletion() throws Exception {
        InMemoryStorage<String, StoredRole> store = spy(new InMemoryStorage<>());
        IamRoleService racing = new IamRoleService(store, projects);
        StoredRole created = racing.create("projects/p", "reader", role("Reader", "pubsub.topics.get"));
        CountDownLatch reached = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        doAnswer(invocation -> {
            reached.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return invocation.callRealMethod();
        }).when(store).put(anyString(), any());
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> deletion = executor.submit(() -> racing.delete(ROLE, created.getEtag()));
            assertTrue(reached.await(5, TimeUnit.SECONDS));
            CountDownLatch started = new CountDownLatch(1);
            Future<?> update = executor.submit(() -> {
                started.countDown();
                racing.update(ROLE, Map.of("includedPermissions", List.of("pubsub.topics.delete"),
                        "etag", created.getEtag()), "includedPermissions");
            });
            assertTrue(started.await(5, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> update.get(100, TimeUnit.MILLISECONDS));
            release.countDown();
            deletion.get(5, TimeUnit.SECONDS);
            ExecutionException failure = assertThrows(ExecutionException.class, () -> update.get(5, TimeUnit.SECONDS));
            assertEquals("ABORTED", ((GcpException) failure.getCause()).getGcpStatus());
            assertEquals(Boolean.TRUE, racing.get(ROLE).getDeleted());
            assertEquals(List.of("pubsub.topics.get"), racing.get(ROLE).getIncludedPermissions());
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private static Map<String, Object> role(String title, String permission) {
        return Map.of("title", title, "includedPermissions", List.of(permission));
    }

    private static ProjectRecord project(String id, String parentType, String parentId) {
        ProjectRecord record = new ProjectRecord();
        record.setProjectId(id);
        record.setParentType(parentType);
        record.setParentId(parentId);
        return record;
    }

    private static void assertStatus(String status, Runnable call) {
        GcpException error = assertThrows(GcpException.class, call::run);
        assertEquals(status, error.getGcpStatus());
    }
}
