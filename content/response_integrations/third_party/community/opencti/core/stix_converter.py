from __future__ import annotations
import stix2

DATETIME_DEFAULT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def convert_to_incident(name, description, severity, incident_date):
    
    bundle_objects = []

    # incident date
    if incident_date is None:
        dateTimeObj = datetime.utcnow()
        incident_date = dateTimeObj.strftime(DATETIME_DEFAULT_FORMAT)

    # manage marking
    #marking = alert_params.get("tlp")
    #marking_id = _get_stix_marking_id(marking)

    # manage author
    #stix_author = stix2.Identity(
    #    name=event.get("host", "Splunk"),
    #    identity_class="system"
    #)
    #bundle_objects.append(stix_author)

    # observables extraction
    #observable_ref_ids = []
    #if alert_params.get("observables_extraction") == "cim_model":
    #    observables = _extract_observables_from_cim_model(
    #        event=event,
    #        marking=marking_id,
    #        creator=stix_author)
    #    for observable in observables:
    #        bundle_objects.append(observable)
    #        observable_ref_ids.append(observable.id)
    #if alert_params.get("observables_extraction") == "field_mapping":
    #    observables = _extract_observables_from_key_model(
    #        event=event,
    #        marking=marking_id,
    #        creator=stix_author)
    #    for observable in observables:
    #        bundle_objects.append(observable)
    #        observable_ref_ids.append(observable.id)

    # create incident
    stix_incident = stix2.Incident(
        name=name,
        created=incident_date,
        description=description,
        object_marking_refs=[],
        external_references=[],
        labels=[],
        allow_custom=True,
        custom_properties={
        #    "source": event.get("host", "Splunk"),
            "severity": severity,
        #    "incident_type": alert_params.get("type"),
        #    "first_seen": event_date
        }
    )
    bundle_objects.append(stix_incident)

    #for observable_id in observable_ref_ids:
    #    stix_relation_account = stix2.Relationship(
    #        relationship_type="related-to",
    #        target_ref=stix_incident.id,
    #        created_by_ref=stix_author.id)
    #    bundle_objects.append(stix_relation_account)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()