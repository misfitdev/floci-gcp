package io.floci.gcp.services.iam;

import com.fasterxml.jackson.core.type.TypeReference;
import io.floci.gcp.core.common.GcpException;
import io.floci.gcp.core.common.PageToken;
import io.floci.gcp.core.common.ProjectRecord;
import io.floci.gcp.core.common.ProjectRegistry;
import io.floci.gcp.core.storage.StorageBackend;
import io.floci.gcp.core.storage.StorageFactory;
import io.floci.gcp.services.iam.model.StoredRole;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Project and organization custom roles ({@code projects.roles}, {@code organizations.roles}) and
 * the permissions their bindings contribute to policy evaluation. Roles are keyed by their full
 * resource name. Deleted roles are kept with {@code deleted=true} and never purged.
 */
@ApplicationScoped
public class IamRoleService {

    private static final Pattern PARENT = Pattern.compile("(projects|organizations)/([^/:]+)");
    private static final Pattern ROLE_NAME = Pattern.compile("((projects|organizations)/([^/:]+))/roles/([^/:]+)");
    private static final Pattern ROLE_ID = Pattern.compile("[A-Za-z0-9_.]{3,64}");
    private static final Set<String> STAGES = Set.of("ALPHA", "BETA", "GA", "DEPRECATED", "DISABLED", "EAP");
    private static final Set<String> MUTABLE_FIELDS = Set.of("title", "description", "includedPermissions", "stage");
    private static final int DEFAULT_PAGE_SIZE = 300;
    private static final int MAX_PAGE_SIZE = 1000;
    private static final int MAX_TITLE_BYTES = 100;
    private static final int MAX_DESCRIPTION_BYTES = 300;
    private static final int MAX_PERMISSIONS = 3000;

    private final StorageBackend<String, StoredRole> roles;
    private final ProjectRegistry projects;

    @Inject
    public IamRoleService(StorageFactory storageFactory, ProjectRegistry projects) {
        this(storageFactory.createGlobal("iam-roles", "iam-roles.json",
                new TypeReference<Map<String, StoredRole>>() {}), projects);
    }

    IamRoleService(StorageBackend<String, StoredRole> roles, ProjectRegistry projects) {
        this.roles = roles;
        this.projects = projects;
    }

    public record RolePage(List<StoredRole> roles, String nextPageToken) {}

    public synchronized StoredRole create(String parent, String roleId, Map<String, Object> role) {
        requireParent(parent);
        if (roleId == null || !ROLE_ID.matcher(roleId).matches()) {
            throw GcpException.invalidArgument("The role ID must be 3 to 64 characters of letters, digits, "
                    + "underscores and periods.");
        }
        String name = parent + "/roles/" + roleId;
        // Deleted roles are never purged here, so their IDs stay reserved as during GCP's deletion window.
        if (roles.get(name).isPresent()) {
            throw GcpException.alreadyExists("A role named " + roleId + " in " + parent + " already exists.");
        }
        StoredRole stored = new StoredRole();
        stored.setName(name);
        apply(stored, role != null ? role : Map.of(), MUTABLE_FIELDS);
        stored.setEtag(newEtag());
        roles.put(name, stored);
        return stored.copy();
    }

    public StoredRole get(String name) {
        return stored(name).copy();
    }

    public RolePage list(String parent, String view, boolean showDeleted, int pageSize, String pageToken) {
        requireParent(parent);
        boolean full = parseView(view);
        if (pageSize < 0) {
            throw GcpException.invalidArgument("page_size must not be negative");
        }
        int size = pageSize == 0 ? DEFAULT_PAGE_SIZE : Math.min(pageSize, MAX_PAGE_SIZE);
        String prefix = parent + "/roles/";
        List<StoredRole> matching = roles.scan(key -> key.startsWith(prefix)).stream()
                .filter(role -> showDeleted || !role.softDeleted())
                .sorted(Comparator.comparing(StoredRole::getName))
                .map(role -> full ? role.copy() : role.basicView())
                .toList();
        PageToken.Page<StoredRole> page = PageToken.paginate(matching, size, pageToken);
        return new RolePage(page.items(), page.nextPageToken());
    }

    public synchronized StoredRole update(String name, Map<String, Object> role, String updateMask) {
        StoredRole stored = stored(name).copy();
        Map<String, Object> source = role != null ? role : Map.of();
        checkEtag(stored, source.get("etag"));
        if (stored.softDeleted()) {
            throw GcpException.failedPrecondition("You can't update a deleted role: " + name);
        }
        apply(stored, source, updateFields(source, updateMask));
        stored.setEtag(newEtag());
        roles.put(name, stored);
        return stored.copy();
    }

    public synchronized StoredRole delete(String name, String etag) {
        StoredRole stored = stored(name).copy();
        checkEtag(stored, etag);
        if (stored.softDeleted()) {
            throw GcpException.failedPrecondition("The role is already deleted: " + name);
        }
        stored.setDeleted(true);
        stored.setEtag(newEtag());
        roles.put(name, stored);
        return stored.copy();
    }

    public synchronized StoredRole undelete(String name, String etag) {
        StoredRole stored = stored(name).copy();
        checkEtag(stored, etag);
        if (!stored.softDeleted()) {
            throw GcpException.failedPrecondition("The role is not deleted: " + name);
        }
        stored.setDeleted(false);
        stored.setEtag(newEtag());
        roles.put(name, stored);
        return stored.copy();
    }

    public static boolean isCustomRole(String role) {
        return role != null && ROLE_NAME.matcher(role).matches();
    }

    /**
     * Permissions a binding of {@code role} contributes in the policy stored under {@code policyResource}.
     * A project role applies only to policies of that project; an organization role applies to the
     * organization's policy and to projects whose recorded parent is that organization. Any other
     * placement, an unknown ancestry, and missing, deleted or disabled roles grant nothing.
     */
    public Set<String> grantedPermissions(String role, String policyResource) {
        if (role == null) {
            return Set.of();
        }
        Matcher matcher = ROLE_NAME.matcher(role);
        if (!matcher.matches() || !inScope(matcher.group(2), matcher.group(3), policyResource)) {
            return Set.of();
        }
        return roles.get(role).filter(StoredRole::grantsPermissions)
                .map(stored -> Set.copyOf(stored.getIncludedPermissions()))
                .orElse(Set.of());
    }

    /** Whether {@code role} is an active custom role that applies to the policy under {@code policyResource}. */
    public boolean applies(String role, String policyResource) {
        if (role == null) {
            return false;
        }
        Matcher matcher = ROLE_NAME.matcher(role);
        return matcher.matches() && inScope(matcher.group(2), matcher.group(3), policyResource)
                && roles.get(role).filter(StoredRole::grantsPermissions).isPresent();
    }

    private boolean inScope(String parentType, String parentId, String policyResource) {
        String project = projectOf(policyResource);
        if (parentType.equals("projects")) {
            return parentId.equals(project);
        }
        if (policyResource.equals("organizations/" + parentId)) {
            return true;
        }
        if (project == null) {
            return false;
        }
        Optional<ProjectRecord> record = projects.find(project);
        return record.isPresent() && "organization".equals(record.get().getParentType())
                && parentId.equals(record.get().getParentId());
    }

    private static String projectOf(String policyResource) {
        String[] parts = policyResource.split("/", 3);
        if (parts.length < 2 || !parts[0].equals("projects") || parts[1].isBlank()
                || parts[1].equals("-") || parts[1].equals("_")) {
            return null;
        }
        return parts[1];
    }

    private StoredRole stored(String name) {
        if (name == null || !ROLE_NAME.matcher(name).matches()) {
            throw GcpException.invalidArgument("Invalid role name: " + name);
        }
        requireParent(name.substring(0, name.indexOf("/roles/")));
        return roles.get(name).orElseThrow(() -> GcpException.notFound("The role named " + name + " was not found."));
    }

    private static void requireParent(String parent) {
        Matcher matcher = parent == null ? null : PARENT.matcher(parent);
        if (matcher == null || !matcher.matches() || matcher.group(2).equals("-") || matcher.group(2).equals("*")) {
            throw GcpException.invalidArgument("You must specify a complete project ID or organization ID: " + parent);
        }
    }

    private static boolean parseView(String view) {
        if (view == null || view.isEmpty() || view.equals("BASIC")) {
            return false;
        }
        if (view.equals("FULL")) {
            return true;
        }
        throw GcpException.invalidArgument("Invalid value for view: " + view);
    }

    /** An absent mask updates the populated fields of the request role (AIP-134). */
    private static Set<String> updateFields(Map<String, Object> role, String updateMask) {
        Set<String> fields = new LinkedHashSet<>();
        if (updateMask == null || updateMask.isBlank()) {
            for (String field : MUTABLE_FIELDS) {
                if (role.get(field) != null) {
                    fields.add(field);
                }
            }
            return fields;
        }
        for (String path : updateMask.split(",")) {
            String field = path.trim().equals("included_permissions") ? "includedPermissions" : path.trim();
            if (!MUTABLE_FIELDS.contains(field)) {
                throw GcpException.invalidArgument("Invalid update mask path: " + path.trim());
            }
            fields.add(field);
        }
        return fields;
    }

    private static void apply(StoredRole target, Map<String, Object> source, Set<String> fields) {
        if (fields.contains("title")) {
            String title = stringField(source, "title");
            requireMaxBytes("title", title, MAX_TITLE_BYTES);
            target.setTitle(title);
        }
        if (fields.contains("description")) {
            String description = stringField(source, "description");
            requireMaxBytes("description", description, MAX_DESCRIPTION_BYTES);
            target.setDescription(description);
        }
        if (fields.contains("includedPermissions")) {
            target.setIncludedPermissions(permissions(source.get("includedPermissions")));
        }
        if (fields.contains("stage")) {
            Object stage = source.get("stage");
            if (stage != null && !STAGES.contains(stage.toString())) {
                throw GcpException.invalidArgument("Invalid value for stage: " + stage);
            }
            target.setStage(stage != null ? stage.toString() : StoredRole.ALPHA);
        }
    }

    private static String stringField(Map<String, Object> source, String field) {
        Object value = source.get(field);
        if (value != null && !(value instanceof String)) {
            throw GcpException.invalidArgument("Invalid value for " + field);
        }
        return (String) value;
    }

    private static void requireMaxBytes(String field, String value, int max) {
        if (value != null && value.getBytes(StandardCharsets.UTF_8).length > max) {
            throw GcpException.invalidArgument("The role " + field + " must be at most " + max + " bytes.");
        }
    }

    private static List<String> permissions(Object value) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list)) {
            throw GcpException.invalidArgument("Invalid value for includedPermissions");
        }
        if (list.size() > MAX_PERMISSIONS) {
            throw GcpException.invalidArgument("A role can contain at most " + MAX_PERMISSIONS + " permissions.");
        }
        Set<String> permissions = new LinkedHashSet<>();
        for (Object permission : list) {
            if (!(permission instanceof String text) || text.isBlank() || text.contains("*")) {
                throw GcpException.invalidArgument("Permission " + permission + " is not valid.");
            }
            permissions.add(text);
        }
        return new ArrayList<>(permissions);
    }

    private static void checkEtag(StoredRole stored, Object requested) {
        if (requested == null || requested.toString().isEmpty()) {
            return;
        }
        if (!Arrays.equals(etagBytes(requested.toString()), etagBytes(stored.getEtag()))) {
            throw GcpException.aborted("There were concurrent policy changes. Please retry the whole "
                    + "read-modify-write with exponential backoff.");
        }
    }

    /** Clients may re-encode the bytes etag in either base64 alphabet. */
    private static byte[] etagBytes(String etag) {
        try {
            return Base64.getDecoder().decode(etag);
        } catch (IllegalArgumentException standardFailure) {
            try {
                return Base64.getUrlDecoder().decode(etag);
            } catch (IllegalArgumentException urlSafeFailure) {
                throw GcpException.invalidArgument("Invalid etag: " + etag);
            }
        }
    }

    private static String newEtag() {
        byte[] bytes = new byte[8];
        ThreadLocalRandom.current().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
