# Generated by Django 5.0.4 on 2024-04-24 09:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppFinal', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='student',
            name='speciality',
            field=models.CharField(max_length=100, null=True, verbose_name='speciality'),
        ),
    ]