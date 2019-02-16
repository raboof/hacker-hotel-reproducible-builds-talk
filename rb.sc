case class Step(
                 name: String,
                 threats: List[String],
                 mitigations: List[String],
                 objectives: List[String] = Nil,
               ) {
  def left = objectives ++ threats
  override def toString =
    s"""
       |$name
       |Threats:
       |${threats.map(t => "* " + t).mkString("\n")}
     """.stripMargin
}

val model = List(
  Step(
    "&#x2460; &#x1F58B;&#xFE0F; Developers write code",
    List(
      "Malicious contributors",
      "Blackmail, coercion",
      "Compromised dev machine",
    ),
    List(
      "Cannot be prevented",
      "Can we still improve trust?",
    )
  ),
  Step(
    "&#x2461; &#x1F333; Commit to Source Control",
    List(
      "Compromised SCM hosting"
    ),
    List(
      "Signed commits",
      "Detect 'rewriting history'",
      "Audits.", // automatic and manual
      // Anyone can do this!
    )
  ),
  Step(
    "&#x2462; &#x1F3D7;&#xFE0F; Built and packaged",
    List(
      "Malicious dependencies/plugins",
      "Compromised build machine",
    ),
    List(
      "Transitive verification",
      "!!!"
    )
  ),
  Step(
    "&#x2463; &#x1F6A2; Package is distributed",
    List("Compromised distribution infra"),
    List("Signatures.") // unsolved, but out of scope
  ),
  Step(
    "&#x2464; &#x1F60D; User runs software",
    List(),
    List(),
    List("&#x1F945; No malicious code here"),
  )
)

case class Section(
  name: String,
  bullets: List[String],
)

case class Page(name: String, sections: List[Section]) {
  override def toString =
  s"""
# $name

${sections.map { section =>
  s"""
     |${section.name}
     |
     |${section.bullets.map(line => s"* $line").mkString("\n")}
     |
   """.stripMargin
}.mkString("\n")}
  """
}

val processSections: List[Section] = 
  model.map(step => Section(step.name, step.objectives))

def fragment[T](in: List[T]): List[List[T]] =
  in.foldLeft(List.empty[List[T]]){
    case (Nil, elem) => List(List.empty[T], List(elem))
    case (acc, elem) => acc :+ (acc.last :+ elem)
  }

val processModelFragmented: List[List[Section]] =
  fragment[Section](processSections)

val process: Page = Page(
  "OSS Development and Distribution",
  model.map(step => Section(step.name, step.objectives))
)
 
val processFragmented: List[Page] = processModelFragmented.map(sections => Page(
  "OSS Development and Distribution",
  sections
))
 
//val threatModel: Page =
//  Page(
//    "Threat model",
//    "Threats",
//    "",
//    model.map(step => Row(step.name, step.left, List.empty)))

//val threatModelFragmented: List[List[Step]] = {
//  def removeLast(step: List[Step]): List[Step] = {
//    if (step.last.threats.isEmpty) removeLast(step.init) :+ step.last
//    else step.init :+ step.last.copy(threats = step.last.threats.init)
//  }
//  def fragment(steps: List[Step]): List[List[Step]] = {
//    if (steps.flatMap(_.threats).isEmpty)
//      Nil
//    else
//      fragment(removeLast(steps)) :+ steps
//  }
//  fragment(model)
//}
//
//val threatModelPages =
//  threatModelFragmented.map(steps =>
//    Page("Threat model", steps.map(step => Row(step.name, step.left, List.empty)))
//  )

val mitigationsFragmented: List[List[Step]] = {
  def removeLast(step: List[Step]): List[Step] = {
    if (step.last.mitigations.isEmpty) removeLast(step.init) :+ step.last
    else step.init :+ step.last.copy(mitigations = step.last.mitigations.init)
  }
  def fragment(steps: List[Step]): List[List[Step]] = {
    if (steps.flatMap(_.mitigations).isEmpty)
      Nil
    else
      fragment(removeLast(steps)) :+ steps
  }
  fragment(model)
}

def threats(step: Step): List[Page] =
  fragment(step.threats)
    .map(threats => Page(
      step.name,
      List(Section("Threats", threats))
      ))

def mitigations(step: Step): List[Page] =
  fragment(step.mitigations)
    .map(mitigations => Page(
      step.name,
      List(
        Section("Threats", step.threats),
        Section("Mitigations", mitigations)
      ))
    )

def threatsAndMitigations(step: Step): List[Page] =
  threats(step) ++ mitigations(step)

//val mitigationsPages: List[Page] =
//  mitigationsFragmented.map(steps =>
//    Page("Threat model", "Mitigations", steps.map(step => Row(step.name, step.left, step.mitigations)))
//  )

println((processFragmented ++ model.flatMap(threatsAndMitigations(_)) :+ process).mkString("\n---\n"))
