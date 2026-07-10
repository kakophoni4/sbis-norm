# Generated manually for RequirementDocument.external_synced_at

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0008_remove_report_submit_models"),
    ]

    operations = [
        migrations.AddField(
            model_name="requirementdocument",
            name="external_synced_at",
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                null=True,
                verbose_name="Забрано внешним сервисом",
            ),
        ),
    ]
