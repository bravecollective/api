class Permission(object):
    """This is a static class intended to provide applications with an implementation of the Core permission
    wildcard checking. Applications are free to use their own implementation of this, but *MUST* provide the
    exact same results if they do."""

    GRANT_WILDCARD = '*'

    @staticmethod
    def grants_permission(wildcard_perm, granted_perm):
        """This is used to see if a permission grants access to a permission which is not in the Core database.
            For instance, when evaluating whether a WildcardPermission grants access to a run-time permission."""
        # Splits both this permission's id and the permission being checked.
        wild_segments = wildcard_perm.split('.')
        perm_segments = granted_perm.split('.')

        # If the wildcard permission has more segments than the permission we're matching against, it can't provide access
        # to that permission.
        if len(wild_segments) > len(perm_segments):
            return False

        # If the permission we're checking against is longer than the wildcard permission (this permission), then this
        # permission must end in a wildcard for it to grant the checked permission.
        if len(wild_segments) < len(perm_segments):
            if Permission.GRANT_WILDCARD != wild_segments[-1]:
                return False

        # Loops through each segment of the wildcard_perm and permission. 'core.example.*.test.*' would have
        # segments of 'core', 'example', '*', 'test', and '*' in that order.
        for (w_seg, perm_seg) in zip(wild_segments, perm_segments):
            # We loop through looking for something wrong, if there's nothing wrong then we return True.

            # This index is a wildcard, so we skip checks
            if w_seg == Permission.GRANT_WILDCARD:
                continue

            # If this wild segment doesn't match the corresponding segment in the permission, this permission
            # doesn't match, and we return False
            if w_seg != perm_seg:
                return False

        return True

    @staticmethod
    def has_any_permission(perm, wild_perm):
        if Permission.grants_permission(wild_perm, perm):
            return True
        return False

    @staticmethod
    def set_has_any_permission(perms, checked_perm):
        permissions = []
        for p in perms:
            if Permission.has_any_permission(p, checked_perm):
                permissions.append(p)
        return permissions

    @staticmethod
    def set_grants_permission(perms, granted_perm):
        """Loops through a set of permissions and checks if any of them grants permission for granted_perm. Ideal for
            checking if a character/user has the ability to conduct an action"""

        for p in perms:
            if Permission.grants_permission(p, granted_perm):
                return True

        return False