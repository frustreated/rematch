# Generated by Django 2.1.2 on 2018-11-04 04:50

import collab.validators
from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Annotation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.UUIDField(null=True, unique=True)),
                ('type', models.CharField(choices=[('name', 'Name'), ('assembly', 'Assembly'), ('prototype', 'Prototype'), ('structure', 'Structure')], max_length=64)),
                ('data', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='Dependency',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dependency', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='collab.Annotation', to_field='uuid')),
                ('dependent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='collab.Annotation', to_field='uuid')),
            ],
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('name', models.CharField(max_length=256)),
                ('description', models.TextField()),
                ('md5hash', models.CharField(db_index=True, max_length=32, validators=[django.core.validators.MinLengthValidator(32)])),
                ('file', models.FileField(null=True, upload_to='tasks', validators=[collab.validators.idb_validator])),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='FileVersion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('md5hash', models.CharField(max_length=32, validators=[django.core.validators.MinLengthValidator(32)])),
                ('complete', models.BooleanField(default=False)),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='versions', to='collab.File')),
            ],
        ),
        migrations.CreateModel(
            name='Instance',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('empty_data', 'Empty Data'), ('data', 'Data'), ('empty_function', 'Empty Function'), ('function', 'Function'), ('universal', 'Universal')], max_length=64)),
                ('offset', models.BigIntegerField(null=True)),
                ('size', models.BigIntegerField()),
                ('count', models.BigIntegerField()),
                ('file_version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='instances', to='collab.FileVersion')),
            ],
        ),
        migrations.CreateModel(
            name='Match',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('instruction_hash', 'Instruction Hash'), ('identity_hash', 'Identity Hash'), ('name_hash', 'Name Hash'), ('assembly_hash', 'Assembly Hash'), ('mnemonic_hash', 'Mnemonic Hash'), ('mnemonic_euclidean', 'Mnemonic Euclidean Distance'), ('basicblocksize_euclidean', 'Basic Block size Distance')], max_length=64)),
                ('score', models.FloatField()),
                ('from_instance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='from_matches', to='collab.Instance')),
            ],
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('name', models.CharField(max_length=256)),
                ('description', models.TextField()),
                ('private', models.BooleanField()),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('created',),
            },
        ),
        migrations.CreateModel(
            name='Task',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('task_id', models.UUIDField(db_index=True, null=True, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('finished', models.DateTimeField(null=True)),
                ('status', models.CharField(choices=[('pending', 'Pending in Queue...'), ('started', 'Started'), ('done', 'Done!'), ('failed', 'Failure')], default='pending', max_length=64)),
                ('source_start', models.BigIntegerField(null=True)),
                ('source_end', models.BigIntegerField(null=True)),
                ('matchers', models.TextField(default='[]')),
                ('strategy', models.CharField(choices=[('all_strategy', 'All'), ('binning_strategy', 'Binning')], default='all_strategy', max_length=256)),
                ('progress', models.PositiveSmallIntegerField(default=0)),
                ('progress_max', models.PositiveSmallIntegerField(null=True)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('source_file_version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='source_tasks', to='collab.FileVersion')),
                ('target_file', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='collab.File')),
                ('target_project', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='collab.Project')),
            ],
        ),
        migrations.CreateModel(
            name='Vector',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('instruction_hash', 'Instruction Hash'), ('identity_hash', 'Identity Hash'), ('name_hash', 'Name Hash'), ('assembly_hash', 'Assembly Hash'), ('mnemonic_hash', 'Mnemonic Hash'), ('mnemonic_hist', 'Mnemonic Hist'), ('basicblocksize_hist', 'Basic Block Size Hist')], max_length=64)),
                ('type_version', models.IntegerField()),
                ('data', models.TextField()),
                ('file_version', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vectors', to='collab.FileVersion')),
                ('instance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vectors', to='collab.Instance')),
            ],
        ),
        migrations.AddField(
            model_name='match',
            name='task',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='matches', to='collab.Task'),
        ),
        migrations.AddField(
            model_name='match',
            name='to_instance',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='to_matches', to='collab.Instance'),
        ),
        migrations.AddField(
            model_name='instance',
            name='matches',
            field=models.ManyToManyField(related_name='_instance_matches_+', through='collab.Match', to='collab.Instance'),
        ),
        migrations.AddField(
            model_name='instance',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='file',
            name='project',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='files', to='collab.Project'),
        ),
        migrations.AddField(
            model_name='annotation',
            name='dependencies',
            field=models.ManyToManyField(related_name='dependents', through='collab.Dependency', to='collab.Annotation'),
        ),
        migrations.AddField(
            model_name='annotation',
            name='instance',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='annotations', to='collab.Instance'),
        ),
        migrations.AlterUniqueTogether(
            name='vector',
            unique_together={('instance', 'type')},
        ),
        migrations.AlterUniqueTogether(
            name='instance',
            unique_together={('file_version', 'offset')},
        ),
        migrations.AlterUniqueTogether(
            name='fileversion',
            unique_together={('file', 'md5hash')},
        ),
    ]
