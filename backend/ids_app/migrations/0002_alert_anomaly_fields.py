from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ids_app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='alert',
            name='anomaly_score',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='alert',
            name='detection_method',
            field=models.CharField(default='supervised', max_length=30),
        ),
        migrations.AddField(
            model_name='alert',
            name='is_unknown_attack',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='alert',
            name='rf_prediction',
            field=models.CharField(blank=True, default='', max_length=50),
        ),
    ]
