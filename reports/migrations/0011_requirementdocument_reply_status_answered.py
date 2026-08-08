from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0010_requirementdocument_deadline_and_reply"),
    ]

    operations = [
        migrations.AlterField(
            model_name="requirementdocument",
            name="reply_status",
            field=models.CharField(
                choices=[
                    ("none", "Нет ответа"),
                    ("sent", "Отправлен нами"),
                    ("answered", "Отвечено (СБИС)"),
                    ("error", "Ошибка"),
                ],
                db_index=True,
                default="none",
                max_length=16,
                verbose_name="Статус ответа",
            ),
        ),
    ]
