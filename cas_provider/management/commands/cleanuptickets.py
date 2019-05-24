"""
A management command which deletes expired service tickets (e.g.,
from the database.

Calls ``ServiceTickets.objects.delete_expired_users()``, which
contains the actual logic for determining which accounts are deleted.

"""

from django.core.management.base import BaseCommand
from django.conf import settings

import datetime

from cas_provider.models import ServiceTicket, LoginTicket


class Command(BaseCommand):
    help = "Delete expired service tickets from the database"

    def handle(self, *args, **kwargs):
        expiration = datetime.timedelta(minutes=settings.CAS_TICKET_EXPIRATION)
        created_before = datetime.datetime.now() - expiration
        deleted, _ = ServiceTicket.objects.filter(created__lt=created_before).delete()
        print("Deleted ", deleted, "Service Tickets")
        deleted, _ = LoginTicket.objects.filter(created__lt=created_before).delete()
        print("Deleted ", deleted, "Login Tickets")
