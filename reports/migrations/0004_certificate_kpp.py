# Generated manually for Certificate.kpp

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0003_alter_certificate_unique_together_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="kpp",
            field=models.CharField(
                blank=True,
                help_text="Для СБИС и фильтров; можно заполнить sync_org_kpp",
                max_length=9,
                null=True,
                verbose_name="КПП",
            ),
        ),
    ]
