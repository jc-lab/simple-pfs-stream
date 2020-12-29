import payload from './model/payload';

export class AlertError extends Error {
  public readonly alert: payload.Alert;

  constructor(alert: payload.Alert) {
    super(`AlertError: code=${alert.code}, message=${alert.message}`);
    this.alert = alert;
  }
}
