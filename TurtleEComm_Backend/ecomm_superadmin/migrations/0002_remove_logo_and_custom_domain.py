# Generated by Django 5.0.6 on 2025-03-30 13:25

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ecomm_superadmin', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tenant',
            name='description',
        ),
        migrations.RemoveField(
            model_name='tenant',
            name='on_trial',
        ),
        migrations.AlterField(
            model_name='tenant',
            name='client',
            field=models.ForeignKey(default=1, help_text='The CRM client associated with this tenant', on_delete=django.db.models.deletion.CASCADE, related_name='tenants', to='ecomm_superadmin.crmclient'),
            preserve_default=False,
        ),
    ]
