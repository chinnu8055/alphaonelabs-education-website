from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from web.models import PeerMessage


class Command(BaseCommand):
    help = "Deletes direct messages older than 7 days."

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=7)
        expired_qs = PeerMessage.objects.filter(created_at__lt=cutoff)
        count = expired_qs.count()
        expired_qs.delete()
        self.stdout.write(self.style.SUCCESS(f"Successfully deleted {count} expired messages"))
