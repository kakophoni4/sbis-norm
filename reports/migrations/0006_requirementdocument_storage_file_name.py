from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0005_requirementdocument"),
    ]

    operations = [
        migrations.AddField(
            model_name="requirementdocument",
            name="storage_file_name",
            field=models.CharField(
                blank=True,
                max_length=255,
                null=True,
                verbose_name="Имя файла для экспорта (Требование ФНС (ИНН) (дата).pdf)",
            ),
        ),
    ]
