from django.utils.timezone import now, timedelta
from rest_framework.permissions import SAFE_METHODS, BasePermission


class IsOwner(BasePermission):
    def has_permission(self, request, view):
        return (
            request.auth and request.auth.get("user_id") and not request.auth.get("is_staff")
        )

    def has_object_permission(self, request, view, obj):
        return request.auth.get("user_id") == obj.owner_id


class IsAnonymous(BasePermission):
    def has_permission(self, request, view):
        return request.method in SAFE_METHODS


class CanEditSomeTime(BasePermission):
    def has_object_permission(self, request, view, obj):
        passed_time = now() - obj.updated_at
        return passed_time >= timedelta(minutes=1)

class IsModerator(BasePermission):
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated and request.user.is_staff):
            return False

        if request.method == 'POST':
            return False

        return True