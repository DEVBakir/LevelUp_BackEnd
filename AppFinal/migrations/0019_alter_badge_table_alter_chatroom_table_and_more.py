# Generated by Django 5.0.4 on 2024-05-14 15:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AppFinal', '0018_remove_student_img_remove_teacher_img_user_img'),
    ]

    operations = [
        migrations.AlterModelTable(
            name='badge',
            table='badge',
        ),
        migrations.AlterModelTable(
            name='chatroom',
            table='chatRoom',
        ),
        migrations.AlterModelTable(
            name='course',
            table='course',
        ),
        migrations.AlterModelTable(
            name='enroll_course',
            table='enrollCourse',
        ),
        migrations.AlterModelTable(
            name='game',
            table='game',
        ),
        migrations.AlterModelTable(
            name='lesson',
            table='lesson',
        ),
        migrations.AlterModelTable(
            name='message',
            table='message',
        ),
        migrations.AlterModelTable(
            name='onetimepassword',
            table='oneTimePassword',
        ),
        migrations.AlterModelTable(
            name='participation',
            table='participation',
        ),
        migrations.AlterModelTable(
            name='role',
            table='role',
        ),
        migrations.AlterModelTable(
            name='slide',
            table='slide',
        ),
        migrations.AlterModelTable(
            name='student',
            table='student',
        ),
        migrations.AlterModelTable(
            name='teacher',
            table='teacher',
        ),
        migrations.AlterModelTable(
            name='user',
            table='user',
        ),
        migrations.AlterModelTable(
            name='user_roles',
            table='user_role',
        ),
    ]