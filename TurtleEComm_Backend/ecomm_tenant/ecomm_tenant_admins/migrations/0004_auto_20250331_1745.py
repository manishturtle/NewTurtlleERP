# Generated by Django 4.2.10 on 2025-03-31 12:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ecomm_tenant_admins', '0003_auto_20250331_1713'),
    ]

    operations = [
        migrations.RunSQL(
            # Create the TenantUser table if it doesn't exist
            """
            CREATE TABLE IF NOT EXISTS ecomm_tenant_admins_tenantuser (
                id SERIAL PRIMARY KEY,
                password VARCHAR(128) NOT NULL,
                last_login TIMESTAMP WITH TIME ZONE NULL,
                is_superuser BOOLEAN NOT NULL,
                email VARCHAR(254) NOT NULL UNIQUE,
                username VARCHAR(150) NOT NULL,
                first_name VARCHAR(150) NOT NULL,
                last_name VARCHAR(150) NOT NULL,
                is_active BOOLEAN NOT NULL,
                is_staff BOOLEAN NOT NULL,
                date_joined TIMESTAMP WITH TIME ZONE NOT NULL,
                client_id INTEGER NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                created_by VARCHAR(255) NULL,
                updated_by VARCHAR(255) NULL
            );
            """,
            # Drop the table if needed (for reverse migration)
            "DROP TABLE IF EXISTS ecomm_tenant_admins_tenantuser;"
        ),
    ]
