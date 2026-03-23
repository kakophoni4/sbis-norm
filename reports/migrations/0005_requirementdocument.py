# Generated for RequirementDocument (требования ФНС, хранение base64 PDF)

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0004_certificate_kpp"),
    ]

    operations = [
        migrations.CreateModel(
            name="RequirementDocument",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("inn", models.CharField(db_index=True, max_length=12, verbose_name="ИНН")),
                ("document_date", models.DateField(verbose_name="Дата документа")),
                ("sbis_doc_id", models.CharField(db_index=True, max_length=255, verbose_name="Идентификатор документа в СБИС")),
                ("sbis_stage_id", models.CharField(blank=True, max_length=255, null=True, verbose_name="Идентификатор этапа в СБИС")),
                ("doc_title", models.CharField(blank=True, max_length=512, verbose_name="Название документа")),
                ("content_sha256", models.CharField(db_index=True, max_length=64, verbose_name="SHA256 содержимого (для дедупликации)")),
                ("file_b64", models.TextField(verbose_name="Base64 содержимого PDF")),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Создано")),
            ],
            options={
                "verbose_name": "Требование (документ ФНС)",
                "verbose_name_plural": "Требования (документы ФНС)",
                "ordering": ["-document_date", "-created_at"],
                "unique_together": {("inn", "sbis_doc_id")},
            },
        ),
        migrations.AddIndex(
            model_name="requirementdocument",
            index=models.Index(fields=["inn", "document_date", "content_sha256"], name="reports_req_inn_doc_date_sha_idx"),
        ),
    ]
