# Task: Identify Upstream and Downstream Service Dependencies

## 1. Runtime Inputs

The following values are provided dynamically for every request:

- `service_name`: `{{service_name}}`
- `sector`: `{{sector}}`
- `subsector`: `{{subsector}}`
- `entity_context` (optional): `{{entity_context}}`
- `service_inventory` (optional): `{{service_inventory}}`

The service name, sector, and subsector are mandatory. Entity context and service inventory may be provided by the application.

Treat every request independently. Never reuse previous requests' service contexts, candidates, or dependency assumptions without independently validating their applicability.

Do not modify the supplied selected-service values. Use them as the selected service's identity throughout the analysis.

## 2. Objective

Identify defensible, direct upstream and downstream service dependencies for the selected service.

- **Upstream:** A service that the selected service directly requires to perform its operational function.
- **Downstream:** A service that directly requires the selected service's outputs, capabilities, or availability to perform its operational function.

Determine direction exclusively from the selected service's perspective. Do not reverse relationships based on sector, organizational hierarchy, naming conventions, or information-flow direction.

The objective is accuracy and operational relevance, not maximizing the number of results.

## 3. Dynamically Establish Service Context

Before identifying dependencies:

1. Interpret the supplied service name to determine its primary function, responsibilities, operational inputs, outputs, and boundaries.
2. Use the supplied sector to establish the broader industry context.
3. Use the supplied subsector to refine the service's operational meaning.
4. Resolve ambiguity using all three inputs without silently substituting a different service.
5. If material ambiguity remains, identify only relationships justified by the available information.
6. Use optional entity context to determine applicability to specific entities. Do not assume that all entities have identical dependencies.

Construct a service-specific operational context. Do not apply generic industry dependency templates without validating each proposed relationship.

## 4. Permitted Sectors

Every identified dependency must belong to one of these sectors:

1. Advanced & Strategic Manufacturing
2. Community Development
3. Consumer, Health & Essential Goods Manufacturing
4. Economy
5. Education
6. Emergency & Public Safety
7. Energy
8. Environment & Sustainability
9. Health
10. Information and Communication Technology
11. Public Administration
12. Space & Advanced Technology
13. Tourism
14. Transport
15. Urban Planning

Use the exact permitted sector label. Do not force representation from every sector.

Determine a candidate service's subsector from its operational function. If an authoritative subsector taxonomy is supplied, follow it. Otherwise, use a concise, meaningful descriptive subsector without claiming that it is an official classification.

## 5. Service Inventory and Evidence Rules

If a service inventory is provided:

1. Use it as the authoritative source for identifying existing organizational services.
2. Match candidates to inventory entries using service identity and operational meaning, not name similarity alone.
3. Preserve canonical service names and identifiers when supplied.
4. Do not invent inventory identifiers or claim that a candidate exists in the organization unless the inventory confirms it.
5. If the inventory contains no suitable service, return a clearly described candidate only when it is operationally justified. Mark it as unverified.

If no inventory is provided, identify defensible service capabilities using available knowledge. Treat the results as proposed candidates, not verified organizational records.

Use available evidence to support each dependency. Do not fabricate source references, documents, inventory matches, or observed relationships. When direct evidence is unavailable, distinguish a reasoned inference from a verified relationship.

## 6. Dependency Identification Process

### Step 1: Define the operational boundary

Identify the selected service's purpose, necessary inputs, outputs, enabling capabilities, and operating conditions. Exclude its parent organization, unrelated infrastructure, indirect suppliers, and adjacent services unless a direct dependency is established.

### Step 2: Identify upstream services

Include a candidate only when the selected service directly requires its operational capability, output, or availability.

Consider relevant supply services, utilities, communications, information systems, operational inputs, and safety-enabling capabilities where justified.

Do not classify optional, substitutable, or contingency services as universally mandatory. State the relevant operating conditions.

### Step 3: Identify downstream services

Include a candidate only when its operational function directly depends on the selected service's output, capability, or availability.

Exclude indirect recipients, general beneficiaries, remote supply-chain participants, and customers that do not have a demonstrated direct operational dependency.

### Step 4: Evaluate cross-sector relationships

Evaluate candidates across all permitted sectors. Include a cross-sector relationship only when a concrete operational dependency exists.

Shared industry membership, geographic proximity, regulatory oversight, or a common interest is not sufficient evidence of dependency.

### Step 5: Validate each candidate

For every candidate, verify:

- The service is operationally meaningful and sufficiently specific.
- Its sector is in the permitted list.
- Its subsector accurately describes its function.
- The dependency is direct and the direction is correct.
- The dependency reason identifies the actual operational relationship.
- Conditional applicability is explicitly stated.
- The candidate is supported by evidence or clearly marked as an inference.
- Organizational existence is not claimed without inventory confirmation.
- No self-dependency, duplicate, synonymous service, or unjustified reciprocal relationship exists.

Do not exclude a legitimate upstream or downstream relationship merely because the candidate belongs to a different sector.

### Step 6: Validate entity applicability

If multiple entities are supplied, associate each dependency with only the entities for which it is justified.

Do not assume that a dependency applies to all entities. If entity applicability cannot be determined, use an empty applicability list and explain the limitation.

If no entity context is supplied, return an empty applicability list.

### Step 7: Assign confidence and verification status

Assign a confidence score from 0 to 1 based on the strength of the evidence and the specificity of the operational relationship.

- High confidence: strong, specific evidence supports the direct dependency.
- Medium confidence: the relationship is well justified but relies partly on inference or conditional assumptions.
- Low confidence: material uncertainty remains.

Confidence is an estimate, not proof. Do not assign high confidence merely because a relationship is common in the industry.

Use exactly one verification status:

- `verified_inventory`: the candidate's identity is confirmed in the supplied inventory. This does not mean the dependency itself has been independently verified.
- `evidence_supported`: the dependency is supported by supplied evidence, but organizational inventory membership is not confirmed.
- `inferred_candidate`: the dependency is a reasoned inference and lacks direct supporting evidence.

A candidate's verification status must reflect the available information. Do not upgrade the status based solely on LLM-generated reasoning.

## 7. Final Validation

Before producing the response:

1. Confirm the selected-service identity matches the runtime inputs.
2. Confirm each candidate belongs to a permitted sector.
3. Recheck dependency direction from the selected service's perspective.
4. Remove weak, duplicate, indirect, and unsupported candidates.
5. Confirm that applicability, confidence, and verification status are internally consistent.
6. Ensure all required fields exist and use the correct data types.
7. Ensure the output is syntactically valid JSON, with no comments, trailing commas, Markdown, or text outside the JSON object.

If a direction has no defensible dependencies, return an empty array for that direction. Never fabricate results to satisfy a minimum count.

## 8. Required Output Schema

Return exactly this JSON structure:

{
  "selected_service": {
    "service_name": "{{service_name}}",
    "sector": "{{sector}}",
    "subsector": "{{subsector}}",
    "operational_context": "Concise description of the selected service's function and boundaries."
  },
  "upstream_services": [
    {
      "service_name": "Specific operational service name",
      "service_id": null,
      "sector": "Exact permitted sector label",
      "subsector": "Relevant descriptive or authoritative subsector",
      "dependency_type": "Direct",
      "dependency_reason": "Concrete explanation of why the selected service depends on this service.",
      "applicability": "Specific operating conditions, or an explicit statement that the relationship applies generally within the stated context.",
      "applies_to_entities": [],
      "confidence": 0.0,
      "verification_status": "inferred_candidate",
      "evidence": []
    }
  ],
  "downstream_services": [
    {
      "service_name": "Specific operational service name",
      "service_id": null,
      "sector": "Exact permitted sector label",
      "subsector": "Relevant descriptive or authoritative subsector",
      "dependency_type": "Direct",
      "dependency_reason": "Concrete explanation of why this service depends on the selected service.",
      "applicability": "Specific operating conditions, or an explicit statement that the relationship applies generally within the stated context.",
      "applies_to_entities": [],
      "confidence": 0.0,
      "verification_status": "inferred_candidate",
      "evidence": []
    }
  ]
}

### Output Field Rules

- `service_id`: Use the canonical inventory identifier when available; otherwise use null.
- `applies_to_entities`: Use supplied entity identifiers or names, as appropriate. Use an empty array when entity context is unavailable or applicability cannot be established.
- `confidence`: A numeric value between 0 and 1.
- `verification_status`: Must be one of the three defined values.
- `evidence`: An array of actual supporting evidence references or concise evidence descriptions. Use an empty array if none is available; never fabricate references.
- Both dependency arrays may be empty.
- Do not add fields outside the defined schema.

## 9. Final Constraints

- Rebuild the service context dynamically for every invocation.
- Do not hardcode any example service, sector, or subsector.
- Do not invent official service names, organizational records, identifiers, evidence, or dependencies.
- Do not confuse a plausible industry relationship with a verified organizational dependency.
- Do not force cross-sector coverage or a minimum number of results.
- Do not misclassify direct, indirect, upstream, or downstream relationships.
- Prefer fewer, well-justified candidates over numerous weak candidates.
- Return valid JSON only.

Implementation note: Populate the runtime placeholders from the API request. Pass entity context and inventory only when available. Validate the returned JSON against the schema in application code before persisting or displaying recommendations. LLM output must never be treated as automatic approval of a dependency.