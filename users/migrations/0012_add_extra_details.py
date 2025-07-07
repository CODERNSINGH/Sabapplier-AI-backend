# Generated manually for adding extra_details field

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0011_rename_fullname_user_fullname_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='extra_details',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
    ] 