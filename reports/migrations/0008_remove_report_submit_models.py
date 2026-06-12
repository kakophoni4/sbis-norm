from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0007_requirementfetchscanstate"),
    ]

    operations = [
        migrations.DeleteModel(name="WebhookLog"),
        migrations.DeleteModel(name="EventLog"),
        migrations.DeleteModel(name="Document"),
        migrations.DeleteModel(name="Recipient"),
        migrations.DeleteModel(name="ReportType"),
    ]
