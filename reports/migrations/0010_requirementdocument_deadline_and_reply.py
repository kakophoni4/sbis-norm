from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0009_requirementdocument_external_synced_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="requirementdocument",
            name="response_due_date",
            field=models.DateField(
                blank=True,
                db_index=True,
                null=True,
                verbose_name="Крайний срок ответа",
            ),
        ),
        migrations.AddField(
            model_name="requirementdocument",
            name="receipt_due_date",
            field=models.DateField(
                blank=True,
                null=True,
                verbose_name="Срок квитанции о приёме",
            ),
        ),
        migrations.AddField(
            model_name="requirementdocument",
            name="knd",
            field=models.CharField(blank=True, max_length=20, null=True, verbose_name="КНД"),
        ),
        migrations.AddField(
            model_name="requirementdocument",
            name="reply_status",
            field=models.CharField(
                choices=[
                    ("none", "Нет ответа"),
                    ("sent", "Отправлен"),
                    ("error", "Ошибка"),
                ],
                db_index=True,
                default="none",
                max_length=16,
                verbose_name="Статус ответа",
            ),
        ),
        migrations.AddField(
            model_name="requirementdocument",
            name="reply_sbis_doc_id",
            field=models.CharField(
                blank=True,
                max_length=255,
                null=True,
                verbose_name="ID ответа в СБИС",
            ),
        ),
        migrations.AddField(
            model_name="requirementdocument",
            name="replied_at",
            field=models.DateTimeField(blank=True, null=True, verbose_name="Ответ отправлен"),
        ),
        migrations.AddField(
            model_name="requirementdocument",
            name="reply_error",
            field=models.TextField(blank=True, null=True, verbose_name="Ошибка ответа"),
        ),
    ]
