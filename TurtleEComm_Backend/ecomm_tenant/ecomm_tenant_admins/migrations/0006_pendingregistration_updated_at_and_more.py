# Generated by Django 4.2.10 on 2025-04-03 13:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ecomm_tenant_admins', '0005_auto_20250331_1847'),
    ]

    operations = [
        migrations.AddField(
            model_name='pendingregistration',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name='tenantuser',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, help_text='Timestamp when the user was created'),
        ),
        migrations.AlterField(
            model_name='tenantuser',
            name='updated_at',
            field=models.DateTimeField(auto_now=True, help_text='Timestamp when the user was last updated'),
        ),
        migrations.AlterModelTable(
            name='tenantuser',
            table='ecomm_tenant_admins_tenantuser',
        ),
    ]
