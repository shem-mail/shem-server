package org.shem.imap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.james.events.EventBus;
import org.apache.james.imap.api.message.response.StatusResponseFactory;
import org.apache.james.imap.api.process.DefaultMailboxTyper;
import org.apache.james.imap.api.process.ImapProcessor;
import org.apache.james.imap.api.process.MailboxTyper;
import org.apache.james.imap.main.PathConverter;
import org.apache.james.imap.message.response.UnpooledStatusResponseFactory;
import org.apache.james.imap.processor.AppendProcessor;
import org.apache.james.imap.processor.CapabilityImplementingProcessor;
import org.apache.james.imap.processor.CapabilityProcessor;
import org.apache.james.imap.processor.CheckProcessor;
import org.apache.james.imap.processor.CloseProcessor;
import org.apache.james.imap.processor.CopyProcessor;
import org.apache.james.imap.processor.CreateProcessor;
import org.apache.james.imap.processor.DefaultProcessor;
import org.apache.james.imap.processor.DeleteProcessor;
import org.apache.james.imap.processor.EnableProcessor;
import org.apache.james.imap.processor.ExamineProcessor;
import org.apache.james.imap.processor.ExpungeProcessor;
import org.apache.james.imap.processor.IdProcessor;
import org.apache.james.imap.processor.IdleProcessor;
import org.apache.james.imap.processor.LSubProcessor;
import org.apache.james.imap.processor.ListProcessor;
import org.apache.james.imap.processor.LogoutProcessor;
import org.apache.james.imap.processor.MoveProcessor;
import org.apache.james.imap.processor.NamespaceProcessor;
import org.apache.james.imap.processor.NamespaceSupplier;
import org.apache.james.imap.processor.NoopProcessor;
import org.apache.james.imap.processor.PermitEnableCapabilityProcessor;
import org.apache.james.imap.processor.RenameProcessor;
import org.apache.james.imap.processor.SearchProcessor;
import org.apache.james.imap.processor.SelectProcessor;
import org.apache.james.imap.processor.StatusProcessor;
import org.apache.james.imap.processor.StoreProcessor;
import org.apache.james.imap.processor.SubscribeProcessor;
import org.apache.james.imap.processor.SystemMessageProcessor;
import org.apache.james.imap.processor.UnselectProcessor;
import org.apache.james.imap.processor.UnsubscribeProcessor;
import org.apache.james.imap.processor.base.AbstractProcessor;
import org.apache.james.imap.processor.base.ImapResponseMessageProcessor;
import org.apache.james.imap.processor.base.UnknownRequestProcessor;
import org.apache.james.imap.processor.fetch.FetchProcessor;
import org.apache.james.mailbox.MailboxCounterCorrector;
import org.apache.james.metrics.api.MetricFactory;

/**
 * Shem's IMAP processor chain: James's processors for standard commands, Shem's own LOGIN and
 * AUTHENTICATE, and nothing for ACL, QUOTA, METADATA, REPLACE, COMPRESS, or XLIST (not offered
 * until tested against Shem's storage semantics).
 */
final class ImapProcessors {
  private ImapProcessors() {}

  @SuppressWarnings({"rawtypes", "unchecked"}) // DefaultProcessor's map uses raw Class keys
  static ImapProcessor create(
      ShemMailboxManager manager,
      EventBus eventBus,
      ImapAuthentication authentication,
      MetricFactory metrics) {
    StatusResponseFactory status = new UnpooledStatusResponseFactory();
    PathConverter.Factory paths = PathConverter.Factory.DEFAULT;
    MailboxTyper typer = new DefaultMailboxTyper();
    MailboxCounterCorrector corrector = MailboxCounterCorrector.DEFAULT;
    CapabilityProcessor capability = new CapabilityProcessor(manager, status, metrics);
    StatusProcessor statusProcessor = new StatusProcessor(manager, status, metrics, paths);
    EnableProcessor enable = new EnableProcessor(manager, status, metrics, capability);
    List<AbstractProcessor> processors =
        List.of(
            new SystemMessageProcessor(),
            new LogoutProcessor(manager, status, metrics),
            capability,
            new IdProcessor(manager, status, metrics),
            new CheckProcessor(manager, status, metrics),
            new ShemLoginProcessor(manager, status, metrics, authentication),
            new ShemAuthenticateProcessor(manager, status, metrics, authentication),
            new RenameProcessor(manager, status, metrics, paths),
            new DeleteProcessor(manager, status, metrics, paths),
            new CreateProcessor(manager, status, metrics, paths),
            new CloseProcessor(manager, status, metrics),
            new UnsubscribeProcessor(manager, manager, status, metrics, paths),
            new SubscribeProcessor(manager, manager, status, metrics, paths),
            new CopyProcessor(manager, status, metrics, paths),
            new MoveProcessor(manager, status, metrics, paths),
            new ExpungeProcessor(manager, status, metrics),
            new ExamineProcessor(manager, eventBus, status, metrics, paths, corrector),
            new AppendProcessor(manager, status, metrics, paths),
            new StoreProcessor(manager, status, metrics),
            new NoopProcessor(manager, status, metrics),
            new IdleProcessor(manager, status, metrics),
            statusProcessor,
            new LSubProcessor(manager, manager, status, metrics, paths),
            new ListProcessor<>(manager, status, metrics, manager, statusProcessor, typer, paths),
            new SearchProcessor(manager, status, metrics),
            new SelectProcessor(manager, eventBus, status, metrics, paths, corrector),
            new NamespaceProcessor(manager, status, metrics, new NamespaceSupplier.Default()),
            new FetchProcessor(
                manager, status, metrics, FetchProcessor.LocalCacheConfiguration.DEFAULT),
            new UnselectProcessor(manager, status, metrics),
            enable,
            new ImapResponseMessageProcessor());
    for (AbstractProcessor processor : processors) {
      if (processor instanceof CapabilityImplementingProcessor c) {
        capability.addProcessor(c);
      }
      if (processor instanceof PermitEnableCapabilityProcessor p) {
        enable.addProcessor(p);
      }
    }
    Map<Class, ImapProcessor> byRequest = new HashMap<>();
    for (AbstractProcessor processor : processors) {
      for (Object type : processor.acceptableClasses()) {
        byRequest.put((Class) type, processor);
      }
    }
    return new DefaultProcessor(byRequest, new UnknownRequestProcessor(status));
  }
}
