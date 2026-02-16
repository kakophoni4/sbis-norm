from rest_framework import serializers
from .models import Document, EventLog

class EventLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventLog
        fields = ['event_type', 'timestamp', 'details']

class DocumentStatusSerializer(serializers.ModelSerializer):
    events = EventLogSerializer(many=True, read_only=True)

    class Meta:
        model = Document
        fields = ['id', 'status', 'created_at', 'updated_at', 'events']

class DocumentCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ['id', 'status', 'created_at']
        read_only_fields = fields
