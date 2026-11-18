from django.shortcuts import redirect

EXEMPT_PREFIXES = ("/onboarding/", "/accounts/", "/admin/", "/static/", "/media/")


class RequireOrganizationMiddleware:
    """Signed-in users without an organization are sent to set one up first."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if (user is not None and user.is_authenticated and not user.organization_id
                and not request.path.startswith(EXEMPT_PREFIXES)):
            return redirect("/onboarding/")
        return self.get_response(request)
