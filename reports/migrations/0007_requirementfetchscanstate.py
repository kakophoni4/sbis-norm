# Generated manually for RequirementFetchScanState

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0006_requirementdocument_storage_file_name"),
    ]

    operations = [
        migrations.CreateModel(
            name="RequirementFetchScanState",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("inn", models.CharField(db_index=True, max_length=12, verbose_name="ИНН")),
                ("window_key", models.CharField(db_index=True, max_length=64, verbose_name="Ключ окна (date_from|date_to)")),
                ("scan_date", models.DateField(db_index=True, verbose_name="Календарный день успешного сканирования")),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Создано")),
            ],
            options={
                "verbose_name": "Отметка сканирования требований",
                "verbose_name_plural": "Отметки сканирования требований",
            },
        ),
        migrations.AddConstraint(
            model_name="requirementfetchscanstate",
            constraint=models.UniqueConstraint(
                fields=("inn", "window_key", "scan_date"),
                name="uniq_req_fetch_scan_inn_window_day",
            ),
        ),
    ]
