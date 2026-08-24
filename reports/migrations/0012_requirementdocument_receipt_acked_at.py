from django.db import migrations, models
from django.utils import timezone


def mark_existing_acked(apps, schema_editor):
    """Старые документы уже подтверждались при скане — не трогаем массово."""
    RequirementDocument = apps.get_model("reports", "RequirementDocument")
    now = timezone.now()
    RequirementDocument.objects.filter(receipt_acked_at__isnull=True).update(
        receipt_acked_at=now
    )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0011_requirementdocument_reply_status_answered"),
    ]

    operations = [
        migrations.AddField(
            model_name="requirementdocument",
            name="receipt_acked_at",
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                help_text=(
                    "Когда отправили квитанцию «Подтвердить получение/Утверждение». "
                    "Сканер не подтверждает сразу — отложенный ack через N дней после created_at."
                ),
                null=True,
                verbose_name="Подтверждение получения в СБИС",
            ),
        ),
        migrations.RunPython(mark_existing_acked, noop_reverse),
    ]
